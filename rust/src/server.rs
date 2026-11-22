//! The HTTP server: the router, the one request log, and the edge that turns
//! what hyper reads into a `Request` a handler can use.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use serde_json::json;
use tokio::net::TcpListener;
use url::Url;

use crate::app::App;
use crate::error::{Error, Result};
use crate::http::{error_response, json as json_response, Request, Response, MAX_BODY_BYTES};
use crate::net::client_ip;

pub struct Ctx {
    pub req: Request,
    pub params: HashMap<String, String>,
    /// The client's address (net.rs client_ip), or None when unknown.
    pub ip: Option<String>,
    pub app: App,
}

impl Ctx {
    pub fn param(&self, name: &str) -> &str {
        self.params.get(name).map(String::as_str).unwrap_or("")
    }

    pub fn ip(&self) -> Option<&str> {
        self.ip.as_deref()
    }
}

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
pub type Handler = fn(Ctx) -> BoxFuture<Result<Response>>;

pub struct Route {
    /// Logged in place of the request path, whose query string can carry a
    /// code or a token (docs/DESIGN.md §9.3).
    pub name: &'static str,
    pub methods: Vec<(&'static str, Handler)>,
    /// Served without loading the services: health checks and static files
    /// need nothing a request reads from the database.
    pub bare: bool,
}

/// Exact paths and `:param` segments. A parameter is one path segment of
/// unreserved characters, so nothing in it needs decoding.
#[derive(Default)]
pub struct Router {
    routes: Vec<Route>,
    exact: HashMap<&'static str, usize>,
    patterns: Vec<(Vec<&'static str>, usize)>,
}

// `^[A-Za-z0-9._~-]{1,128}$`
fn is_param(part: &str) -> bool {
    (1..=128).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
}

impl Router {
    pub fn add(&mut self, pattern: &'static str, name: &'static str, methods: Vec<(&'static str, Handler)>, bare: bool) -> &mut Router {
        let index = self.routes.len();
        self.routes.push(Route { name, methods, bare });
        if pattern.contains("/:") {
            self.patterns.push((pattern.split('/').collect(), index));
        } else {
            self.exact.insert(pattern, index);
        }
        self
    }

    pub fn find(&self, pathname: &str) -> Option<(&Route, HashMap<String, String>)> {
        if let Some(i) = self.exact.get(pathname) {
            return Some((&self.routes[*i], HashMap::new()));
        }
        let parts: Vec<&str> = pathname.split('/').collect();
        'patterns: for (segments, index) in &self.patterns {
            if segments.len() != parts.len() {
                continue;
            }
            let mut params = HashMap::new();
            for (seg, part) in segments.iter().zip(parts.iter()) {
                match seg.strip_prefix(':') {
                    Some(name) if is_param(part) => {
                        params.insert(name.to_string(), part.to_string());
                    }
                    Some(_) => continue 'patterns,
                    None if seg == part => {}
                    None => continue 'patterns,
                }
            }
            return Some((&self.routes[*index], params));
        }
        None
    }
}

/// Wraps an `async fn(Ctx) -> Result<Response>` as a route's handler.
macro_rules! h {
    ($f:path) => {{
        fn handler(ctx: $crate::server::Ctx) -> $crate::server::BoxFuture<$crate::error::Result<$crate::http::Response>> {
            Box::pin($f(ctx))
        }
        handler as $crate::server::Handler
    }};
}
pub(crate) use h;

pub async fn healthz(ctx: Ctx) -> Result<Response> {
    if ctx.app.ready.load(Ordering::SeqCst) && ctx.app.pinger.ping().await {
        Ok(json_response(200, &json!({ "status": "ok" })))
    } else {
        Ok(error_response(503, "temporarily_unavailable", "The database is unreachable.", &[]))
    }
}

pub async fn handle(app: &App, router: &Router, req: Request, ip: Option<String>) -> Response {
    let started = Instant::now();
    let method = req.method.clone();
    let found = router.find(req.path());
    let name = found.as_ref().map_or("unmatched", |(route, _)| route.name);
    let res = match found {
        None => error_response(404, "not_found", "No such endpoint.", &[]),
        Some((route, params)) => match route.methods.iter().find(|(m, _)| *m == method) {
            None => {
                let allowed: Vec<&str> = route.methods.iter().map(|(m, _)| *m).collect();
                error_response(405, "method_not_allowed", &format!("Use {}.", allowed.join(" or ")), &[("Allow".to_string(), allowed.join(", "))])
            }
            // Postgres's text can't hold one, and every list's filters reach it.
            Some(_) if req.path().starts_with("/v1/") && req.url.query_pairs().any(|(k, v)| k.contains('\0') || v.contains('\0')) => {
                error_response(400, "invalid_request", "No query parameter may hold a NUL character.", &[])
            }
            Some((_, handler)) => {
                let (handler, bare, scope) = (*handler, route.bare, app.clone());
                // On a task of its own: a handler that panics answers 500 like
                // any other failure, instead of dropping the connection.
                let outcome = tokio::spawn(async move {
                    let scoped = if bare { scope } else { scope.prepare().await? };
                    handler(Ctx { req, params, ip, app: scoped }).await
                })
                .await;
                match outcome {
                    Ok(Ok(res)) => res,
                    Ok(Err(Error::Http(e))) => e.response(),
                    other => {
                        // The error's name only: a message can quote a query, a
                        // token or a connection string.
                        let thrown = match &other {
                            Ok(Err(e)) => e.name(),
                            _ => "Panic",
                        };
                        app.log(&format!("{method} {name} threw {thrown}"));
                        error_response(500, "server_error", "Internal error.", &[])
                    }
                }
            }
        },
    };
    // A probe every few seconds would bury everything else.
    if !(name == "healthz" && res.status == 200) {
        app.log(&format!("{method} {name} {} {}ms", res.status, started.elapsed().as_millis()));
    }
    res
}

type HyperResponse = hyper::Response<Full<Bytes>>;

fn to_hyper(res: Response) -> HyperResponse {
    let mut builder = hyper::Response::builder().status(res.status);
    for (name, value) in &res.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder.body(Full::new(Bytes::from(res.body))).unwrap_or_else(|_| {
        let mut fallback = hyper::Response::new(Full::new(Bytes::new()));
        *fallback.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
        fallback
    })
}

// A request the server refuses before any handler sees it: answered bare, and
// the connection closed.
fn refuse(status: u16) -> HyperResponse {
    to_hyper(Response { status, headers: vec![("Connection".to_string(), "close".to_string())], body: Vec::new() })
}

async fn serve_request(app: App, router: Arc<Router>, peer: SocketAddr, req: hyper::Request<Incoming>) -> std::result::Result<HyperResponse, std::convert::Infallible> {
    let (parts, body) = req.into_parts();
    let mut headers: Vec<(String, String)> = Vec::with_capacity(parts.headers.len());
    for (name, value) in &parts.headers {
        // One character per byte, as the Fetch standard (and so Bun) reads a
        // header: bytes that are UTF-8 aren't decoded as it.
        headers.push((name.as_str().to_string(), value.as_bytes().iter().map(|&b| char::from(b)).collect()));
    }
    let header = |name: &str| headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str());
    // The URL is the Host and the target: a Host that isn't one host and
    // port alone (empty, or with a path, a query, a user, a backslash, a
    // space or a character outside ASCII, which Bun refuses to make a URL
    // of) is refused bare, as one that is missing.
    let Some(host) = header("host").or(parts.uri.authority().map(|a| a.as_str())) else { return Ok(refuse(400)) };
    let bare_host = !host.is_empty() && host.bytes().all(|b| b.is_ascii_graphic() && !matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\'));
    if !bare_host || Url::parse(&format!("http://{host}/")).is_err() {
        return Ok(refuse(400));
    }
    let target = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let Ok(url) = Url::parse(&format!("http://{host}{target}")) else { return Ok(refuse(400)) };
    let method = parts.method.as_str().to_string();

    let real_ip: Vec<&str> = headers.iter().filter(|(n, _)| n == "x-real-ip").map(|(_, v)| v.as_str()).collect();
    let peer_ip = peer.ip().to_canonical().to_string();
    let ip = client_ip(Some(&peer_ip), (!real_ip.is_empty()).then(|| real_ip.join(", ")).as_deref(), &app.config.trusted_proxies);

    // Every body is capped before it is parsed (§10).
    let mut bytes = Vec::new();
    if method != "GET" && method != "HEAD" {
        let declared = header("content-length").and_then(|l| l.trim().parse::<u64>().ok()).unwrap_or(0);
        if declared > MAX_BODY_BYTES as u64 {
            return Ok(refuse(413));
        }
        match Limited::new(body, MAX_BODY_BYTES).collect().await {
            Ok(collected) => bytes = collected.to_bytes().to_vec(),
            Err(e) if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() => return Ok(refuse(413)),
            Err(_) => return Ok(refuse(400)),
        }
    }

    // Migrations need the database, which may still be starting; until they
    // have run, every request but /healthz answers 503.
    if !app.ready.load(Ordering::SeqCst) && url.path() != "/healthz" {
        return Ok(to_hyper(error_response(503, "temporarily_unavailable", "Starting up.", &[("Retry-After".to_string(), "5".to_string())])));
    }
    let request = Request { method, url, headers, body: bytes };
    Ok(to_hyper(handle(&app, &router, request, ip).await))
}

/// Serves until `stop` settles, then finishes the requests in flight.
pub async fn serve(app: App, router: Arc<Router>, listener: TcpListener, stop: impl Future<Output = ()>) {
    let mut http = hyper::server::conn::http1::Builder::new();
    http.title_case_headers(true).timer(TokioTimer::new());
    let graceful = GracefulShutdown::new();
    tokio::pin!(stop);
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(connection) => connection,
                Err(_) => continue,
            },
            _ = &mut stop => break,
        };
        let _ = stream.set_nodelay(true);
        let (app, router) = (app.clone(), router.clone());
        let connection = http.serve_connection(TokioIo::new(stream), service_fn(move |req| serve_request(app.clone(), router.clone(), peer, req)));
        let connection = graceful.watch(connection);
        tokio::spawn(async move {
            let _ = connection.await;
        });
    }
    drop(listener);
    graceful.shutdown().await;
}
