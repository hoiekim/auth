//! auth: an identity and access service (docs/DESIGN.md). This is the same
//! server as ../src, in Rust: `auth` runs it, `auth cli <command>` is the
//! break-glass CLI.

mod access;
mod api;
mod app;
mod audit;
mod cbor;
mod cli;
mod clients;
mod config;
mod credentials;
mod crypto;
mod db;
mod emails;
mod error;
mod events;
mod factors;
mod http;
mod imports;
mod invites;
mod jobs;
mod json;
mod jwt;
mod keys;
mod mail;
mod migrate;
mod net;
mod oauth;
mod pages;
mod passkeys;
mod passwords;
mod pgurl;
mod registry;
mod rekey;
mod routes;
mod server;
mod services;
mod sessions;
mod throttle;
mod tls;
mod tokens;
mod totp;
mod users;
mod util;
mod webauthn;
mod x509;

use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::signal::unix::{signal, SignalKind};

use crate::app::App;
use crate::config::{load_config, ConfigError};
use crate::error::{Error, Result};

// A parsed JSON value can nest as deep as its input: 32,768 levels in a
// 64 KiB request body, as `JSON.parse` takes it (rust/src/json.rs). Dropping,
// cloning, comparing or printing a serde_json value takes a stack frame for
// each level, up to about 250 bytes in a release build, so 8 MiB for that
// body; the 2 MiB a thread gets by default would let one request abort the
// process. Values from larger inputs, an import or the services file, are
// held in `json::Held`, which takes them apart without recursion.
const STACK_BYTES: usize = 32 * 1024 * 1024;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_stack_size(STACK_BYTES).enable_all().build().expect("the async runtime");
    // On the runtime's threads, with their stacks, rather than on this one.
    let on_runtime = |work: std::pin::Pin<Box<dyn std::future::Future<Output = u8> + Send>>| {
        runtime.block_on(async {
            match tokio::spawn(work).await {
                Ok(code) => code,
                Err(e) => std::panic::resume_unwind(e.into_panic()),
            }
        })
    };
    let code = match args.first().map(String::as_str) {
        None => on_runtime(Box::pin(serve())),
        Some("cli") => {
            let rest = args[1..].to_vec();
            on_runtime(Box::pin(async move { cli::main(&rest).await }))
        }
        Some("healthcheck") => healthcheck(),
        Some(_) => {
            eprintln!(
                "usage: auth                  run the server\n       auth cli <command>    the break-glass CLI (auth cli help)\n       auth healthcheck      exit 0 when the server on PORT is healthy"
            );
            2
        }
    };
    // Tasks still waiting on a peer that will never answer don't hold the exit.
    runtime.shutdown_timeout(Duration::from_secs(1));
    ExitCode::from(code)
}

// The image's HEALTHCHECK: asks the server in this container for /healthz, so
// the image needs no other HTTP client.
fn healthcheck() -> u8 {
    use std::io::{Read, Write};
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.trim().parse().ok()).unwrap_or(3000);
    let healthy = || -> std::io::Result<bool> {
        let mut stream = std::net::TcpStream::connect_timeout(&std::net::SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let mut status = [0u8; 12];
        stream.read_exact(&mut status)?;
        Ok(&status == b"HTTP/1.1 200")
    };
    u8::from(!healthy().unwrap_or(false))
}

pub fn config_from_environment() -> std::result::Result<config::Config, ConfigError> {
    load_config(&|name| std::env::var(name).ok(), &|path| std::fs::read_to_string(path))
}

// Brings the database to where the server can use it: the schema, the
// registered services this configuration can serve, and a signing key.
async fn bring_up(app: &App) -> Result<Option<Vec<String>>> {
    migrate::migrate(&app.pool, |line| app.log(line)).await?;
    // The registered services, checked against this configuration as the
    // file's are at load.
    let problems = registry::registered_problems(app.db(), app.config.api_key_prefix.as_deref()).await?;
    if !problems.is_empty() {
        return Ok(Some(problems));
    }
    keys::rotate_keys(&app.pool, &app.crypt).await?;
    app.keys.refresh(true, app.db()).await?;
    registry::note_held(app).await?;
    Ok(None)
}

async fn serve() -> u8 {
    let config = match config_from_environment() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{}", e.message());
            return 1;
        }
    };
    let port = config.port;
    let (pool, mailer) = match (db::connect(&config.database_url), mail::Mailer::new(config.smtp.clone(), &config.email_from)) {
        (Ok(pool), Ok(mailer)) => (pool, mailer),
        _ => {
            eprintln!("invalid configuration");
            return 1;
        }
    };
    let app = App::new(config, pool, mailer, false);
    let router = Arc::new(routes::build_router());

    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
        Ok(listener) => listener,
        Err(_) => {
            eprintln!("can't listen on :{port}");
            return 1;
        }
    };
    // A deploy stops the old copy with SIGTERM while the new one serves.
    // Requests in flight finish; new ones go to the other copy. Listened for
    // before the server says it listens: a stop that follows at once is never
    // the default kill.
    let (mut term, mut int) = (signal(SignalKind::terminate()).expect("SIGTERM"), signal(SignalKind::interrupt()).expect("SIGINT"));
    println!("listening on :{port}");

    let (stop, stopped) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(server::serve(app.clone(), router, listener, {
        let mut stopped = stopped.clone();
        async move {
            let _ = stopped.wait_for(|s| *s).await;
        }
    }));

    // Migrations need the database, which may still be starting; until they
    // have run, every request but /healthz answers 503.
    let starting = tokio::spawn({
        let (app, mut stopped) = (app.clone(), stopped.clone());
        async move {
            let mut attempt: u64 = 1;
            loop {
                // A stop doesn't wait for an attempt in flight: a database that
                // never answers would hold it past the stop's grace period.
                let attempt_made = tokio::select! {
                    outcome = bring_up(&app) => outcome,
                    _ = stopped.wait_for(|s| *s) => return None,
                };
                match attempt_made {
                    Ok(None) => break,
                    Ok(Some(problems)) => {
                        eprintln!("{}", ConfigError { problems }.message());
                        std::process::exit(1);
                    }
                    Err(Error::UnreadableKey(kid)) => app.log(&format!("start: signing key {kid} has an unreadable public key, retrying")),
                    Err(e) => app.log(&format!("start: database not ready ({}), retrying", e.name())),
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis((1000 * attempt).min(10_000))) => {}
                    _ = stopped.wait_for(|s| *s) => return None,
                }
                attempt += 1;
            }
            app.ready.store(true, Ordering::SeqCst);
            Some(jobs::start_jobs(&app))
        }
    });

    let name = tokio::select! {
        _ = term.recv() => "SIGTERM",
        _ = int.recv() => "SIGINT",
    };
    println!("{name}: finishing requests in flight");
    let _ = stop.send(true);
    let _ = server.await;
    if let Ok(Some(jobs)) = starting.await {
        jobs.stop().await;
    }
    // Emails and alerts the last requests raised go out, within the stop's
    // grace period.
    let _ = tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(app.drain_mail(), app.drain_alerts()) }).await;
    app.pool.close();
    0
}
