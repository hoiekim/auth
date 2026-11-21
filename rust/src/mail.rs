//! Sends auth's emails over SMTP. A body carries one-time links and SMTP_URL
//! can carry a password, so an error names the command and the server's reply
//! code, never the conversation, the body or the URL.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

use crate::crypto::random;
use crate::net::is_ip;
use crate::util::{b64, decode_uri_component, hex, utf16_len};

#[derive(Debug, Clone)]
pub struct MailMessage {
    pub to: String,
    pub subject: String,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SmtpSecurity {
    /// TLS from the first byte.
    Implicit,
    /// The server must offer STARTTLS, and nothing else is sent before it.
    StartTls,
    /// No TLS, allowed only to a loopback host.
    None,
}

#[derive(Debug, Clone)]
pub struct SmtpSettings {
    pub host: String,
    pub port: u16,
    pub secure: SmtpSecurity,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// A failure whose text is safe to log.
#[derive(Debug, Clone)]
pub struct SmtpError(pub String);

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

pub fn parse_smtp_url(value: &str) -> Result<SmtpSettings, &'static str> {
    let url = Url::parse(value).map_err(|_| "SMTP_URL is not a well-formed URL")?;
    if url.scheme() != "smtp" && url.scheme() != "smtps" {
        return Err("SMTP_URL must be an smtp:// or smtps:// URL");
    }
    if (!url.path().is_empty() && url.path() != "/") || url.query().is_some_and(|q| !q.is_empty()) || url.fragment().is_some_and(|f| !f.is_empty()) {
        return Err("SMTP_URL must not have a path, a query or a fragment");
    }
    let hostname = url.host_str().unwrap_or("").to_lowercase();
    let host = hostname.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(&hostname).to_string();
    if !is_host_name(&host) && is_ip(&host) == 0 {
        return Err("SMTP_URL has no valid host");
    }
    let implicit = url.scheme() == "smtps";
    let port = url.port().unwrap_or(if implicit { 465 } else { 587 });
    if port == 0 {
        return Err("SMTP_URL has a port out of range");
    }
    let username = decode_uri_component(url.username()).ok_or("SMTP_URL has a malformed percent-escape")?;
    let password = decode_uri_component(url.password().unwrap_or("")).ok_or("SMTP_URL has a malformed percent-escape")?;
    if username.is_empty() != password.is_empty() {
        return Err("SMTP_URL must give both a user and a password, or neither");
    }
    if username.contains('\0') || password.contains('\0') {
        return Err("SMTP_URL has a NUL byte in its user or password");
    }
    let secure = if implicit {
        SmtpSecurity::Implicit
    } else if is_loopback(&host) {
        SmtpSecurity::None
    } else {
        SmtpSecurity::StartTls
    };
    let credentials = !username.is_empty();
    Ok(SmtpSettings { host, port, secure, username: credentials.then_some(username), password: credentials.then_some(password) })
}

fn is_atom_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+/=?^_`{|}~-".contains(&c)
}

// `^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`
fn is_dns_label(label: &str) -> bool {
    let b = label.as_bytes();
    (1..=63).contains(&b.len())
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

/// Deliberately narrower than RFC 5321: no quoted local parts, no address
/// literals, and a domain with at least one dot whose last label has a letter.
pub fn is_email_address(value: &str) -> bool {
    if utf16_len(value) > 254 {
        return false;
    }
    let Some(at) = value.find('@') else { return false };
    if at < 1 || value.rfind('@') != Some(at) {
        return false;
    }
    let local = &value[..at];
    let labels: Vec<&str> = value[at + 1..].split('.').collect();
    local.len() <= 64
        && local.split('.').all(|atom| !atom.is_empty() && atom.bytes().all(is_atom_char))
        && labels.len() >= 2
        && labels.iter().all(|l| is_dns_label(l))
        && labels.last().is_some_and(|l| l.bytes().any(|b| b.is_ascii_alphabetic()))
}

pub struct Sender {
    pub address: String,
    pub header: String,
}

pub fn parse_from(from: &str) -> Result<Sender, &'static str> {
    const BAD: &str = "EMAIL_FROM must be an address, or a name followed by an address in angle brackets";
    let value = crate::util::js_trim(from);
    // `^(.*?)\s*<([^<>]*)>$`
    let named = value.strip_suffix('>').and_then(|rest| {
        let open = rest.rfind('<')?;
        let (name, address) = (&rest[..open], &rest[open + 1..]);
        let one_line = !name.contains(['\n', '\r', '\u{2028}', '\u{2029}']);
        (one_line && !address.contains('>')).then(|| (name.trim_end_matches(crate::util::is_js_space), address))
    });
    let (mut name, address) = match named {
        Some((name, address)) => (crate::util::js_trim(name).to_string(), address),
        None => (String::new(), value),
    };
    if !is_email_address(address) {
        return Err(BAD);
    }
    if name.len() >= 2 && name.starts_with('"') && name.ends_with('"') && !name.contains(['\n', '\r', '\u{2028}', '\u{2029}']) {
        let inner = &name[1..name.len() - 1];
        let mut unescaped = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    // `\\(.)`: a backslash before a line break stays.
                    Some(next) if !matches!(next, '\n' | '\r' | '\u{2028}' | '\u{2029}') => unescaped.push(next),
                    Some(next) => {
                        unescaped.push('\\');
                        unescaped.push(next);
                    }
                    None => unescaped.push('\\'),
                },
                other => unescaped.push(other),
            }
        }
        name = unescaped;
    }
    if crate::util::has_control(&name) {
        return Err("EMAIL_FROM's name has a control character");
    }
    if name.is_empty() {
        return Ok(Sender { address: address.to_string(), header: address.to_string() });
    }
    Ok(Sender { address: address.to_string(), header: format!("{} <{address}>", display_name(&name)) })
}

fn display_name(name: &str) -> String {
    if !name.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return encoded_words(name);
    }
    if name.bytes().all(|b| is_atom_char(b) || b == b' ') {
        return name.to_string();
    }
    format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
}

fn is_host_name(host: &str) -> bool {
    host.len() <= 253 && host.split('.').all(is_dns_label)
}

// An address literal in 127/8, not just text that looks like one: anything
// else would be resolved through DNS and could lead off the host.
fn is_loopback(host: &str) -> bool {
    host == "localhost" || host == "::1" || (is_ip(host) == 4 && host.starts_with("127."))
}

// `^(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[[0-9A-Fa-f:.]+\])$`
fn is_helo_name(helo: &str) -> bool {
    let name = helo.split('.').all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    let literal = helo.len() > 2
        && helo.starts_with('[')
        && helo.ends_with(']')
        && helo[1..helo.len() - 1].bytes().all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
    name || literal
}

#[derive(Clone)]
pub struct Mailer {
    settings: SmtpSettings,
    address: String,
    header: String,
    helo: String,
    timeout: Duration,
}

impl Mailer {
    pub fn new(settings: SmtpSettings, from: &str) -> Result<Mailer, &'static str> {
        let sender = parse_from(from)?;
        let helo = sender.address[sender.address.rfind('@').map_or(0, |i| i + 1)..].to_string();
        if !is_helo_name(&helo) {
            return Err("smtp: the EHLO name is not a host name");
        }
        if settings.secure == SmtpSecurity::None && !is_loopback(&settings.host) {
            return Err("smtp: plain SMTP is allowed only to a loopback host");
        }
        Ok(Mailer { settings, address: sender.address, header: sender.header, helo, timeout: DEFAULT_TIMEOUT })
    }

    pub async fn send(&self, msg: &MailMessage) -> Result<(), SmtpError> {
        if !is_email_address(&msg.to) {
            return Err(SmtpError("smtp: the recipient is not an email address".into()));
        }
        if msg.subject.contains(['\r', '\n']) {
            return Err(SmtpError("smtp: the subject has a line break".into()));
        }
        let message = self.build_message(msg);
        match tokio::time::timeout(self.timeout, self.deliver(&msg.to, &message)).await {
            Ok(result) => result,
            Err(_) => Err(SmtpError("smtp: timed out".into())),
        }
    }

    fn build_message(&self, msg: &MailMessage) -> String {
        let domain = &self.address[self.address.rfind('@').map_or(0, |i| i + 1)..];
        let normalized = msg.text.replace("\r\n", "\n").replace('\r', "\n").replace('\n', "\r\n");
        let body = b64(normalized.as_bytes());
        let mut lines = vec![
            format!("From: {}", self.header),
            format!("To: {}", msg.to),
            format!("Subject: {}", header_text(&msg.subject)),
            format!("Date: {}", Utc::now().format("%a, %d %b %Y %H:%M:%S +0000")),
            format!("Message-ID: <{}@{domain}>", hex(&random(16))),
            "MIME-Version: 1.0".to_string(),
            "Content-Type: text/plain; charset=utf-8".to_string(),
            "Content-Transfer-Encoding: base64".to_string(),
            String::new(),
        ];
        lines.extend(body.as_bytes().chunks(76).map(|c| String::from_utf8_lossy(c).into_owned()));
        lines.join("\r\n")
    }

    async fn deliver(&self, to: &str, message: &str) -> Result<(), SmtpError> {
        let s = &self.settings;
        let tcp = TcpStream::connect((s.host.as_str(), s.port)).await.map_err(connection_error)?;
        let mut session = if s.secure == SmtpSecurity::Implicit {
            Session::new(Box::new(tls_connect(&s.host, tcp).await?))
        } else {
            Session::new(Box::new(tcp))
        };
        expect_code(&session.read().await?, &[220], "the greeting")?;
        let mut extensions = ehlo(&mut session, &self.helo).await?;
        if s.secure == SmtpSecurity::StartTls {
            if !extensions.iter().any(|(k, _)| k == "STARTTLS") {
                return Err(SmtpError("smtp: the server does not offer STARTTLS".into()));
            }
            session.command("STARTTLS", "STARTTLS", &[220]).await?;
            // Bytes the server sent after its reply to STARTTLS would be read as
            // if they came over TLS, so any are refused.
            if !session.pending.is_empty() {
                return Err(SmtpError("smtp: the server sent data after STARTTLS".into()));
            }
            let plain = session.stream;
            session = Session::new(Box::new(tls_connect(&s.host, plain).await?));
            extensions = ehlo(&mut session, &self.helo).await?;
        }
        if let (Some(username), Some(password)) = (&s.username, &s.password) {
            let plain = extensions.iter().find(|(k, _)| k == "AUTH").is_some_and(|(_, params)| params.iter().any(|p| p == "PLAIN"));
            if !plain {
                return Err(SmtpError("smtp: the server does not offer AUTH PLAIN".into()));
            }
            let token = b64(format!("\0{username}\0{password}").as_bytes());
            session.command(&format!("AUTH PLAIN {token}"), "AUTH", &[235]).await?;
        }
        session.command(&format!("MAIL FROM:<{}>", self.address), "MAIL", &[250]).await?;
        session.command(&format!("RCPT TO:<{to}>"), "RCPT", &[250, 251]).await?;
        session.command("DATA", "DATA", &[354]).await?;
        let stuffed: Vec<String> = message.split("\r\n").map(|l| if l.starts_with('.') { format!(".{l}") } else { l.to_string() }).collect();
        session.command(&format!("{}\r\n.", stuffed.join("\r\n")), "the message", &[250]).await?;
        let _ = session.stream.write_all(b"QUIT\r\n").await;
        let _ = tokio::time::timeout(Duration::from_secs(1), session.stream.shutdown()).await;
        Ok(())
    }
}

fn header_text(text: &str) -> String {
    if text.bytes().all(|b| (0x20..=0x7e).contains(&b)) && text.len() <= 900 {
        text.to_string()
    } else {
        encoded_words(text)
    }
}

// RFC 2047 encoded words of at most 75 characters (45 bytes of UTF-8), split
// between characters, folded onto continuation lines.
fn encoded_words(text: &str) -> String {
    let mut words: Vec<String> = Vec::new();
    let mut chunk: Vec<u8> = Vec::new();
    for ch in text.chars() {
        let mut buf = [0u8; 4];
        let bytes = ch.encode_utf8(&mut buf).as_bytes();
        if chunk.len() + bytes.len() > 45 {
            words.push(format!("=?UTF-8?B?{}?=", b64(&chunk)));
            chunk.clear();
        }
        chunk.extend_from_slice(bytes);
    }
    if !chunk.is_empty() {
        words.push(format!("=?UTF-8?B?{}?=", b64(&chunk)));
    }
    words.join("\r\n ")
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

async fn tls_connect<S: Stream + 'static>(host: &str, stream: S) -> Result<tokio_rustls::client::TlsStream<S>, SmtpError> {
    let name = ServerName::try_from(host.to_string()).map_err(|_| SmtpError("smtp: connection failed".into()))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(crate::tls::client_config()));
    connector.connect(name, stream).await.map_err(connection_error)
}

fn connection_error(e: std::io::Error) -> SmtpError {
    use std::io::ErrorKind::*;
    let code = match e.kind() {
        ConnectionRefused => Some("ECONNREFUSED"),
        ConnectionReset => Some("ECONNRESET"),
        ConnectionAborted => Some("ECONNABORTED"),
        TimedOut => Some("ETIMEDOUT"),
        BrokenPipe => Some("EPIPE"),
        _ => None,
    };
    SmtpError(match code {
        Some(code) => format!("smtp: connection failed ({code})"),
        None => "smtp: connection failed".to_string(),
    })
}

struct Reply {
    code: u16,
    lines: Vec<String>,
}

fn expect_code(reply: &Reply, codes: &[u16], name: &str) -> Result<(), SmtpError> {
    if codes.contains(&reply.code) {
        Ok(())
    } else {
        Err(SmtpError(format!("smtp: server answered {} to {name}", reply.code)))
    }
}

// The extensions EHLO advertises, keyword → parameters, both upper-cased.
async fn ehlo(session: &mut Session, helo: &str) -> Result<Vec<(String, Vec<String>)>, SmtpError> {
    let reply = session.command(&format!("EHLO {helo}"), "EHLO", &[250]).await?;
    Ok(reply
        .lines
        .iter()
        .skip(1)
        .map(|line| {
            let upper = line.trim().to_uppercase();
            let mut words = upper.split_whitespace().map(str::to_string);
            (words.next().unwrap_or_default(), words.collect())
        })
        .collect())
}

const MAX_REPLY_BYTES: usize = 64 * 1024;

// One SMTP connection, read one reply at a time.
struct Session {
    stream: Box<dyn Stream>,
    pending: Vec<u8>,
}

impl Session {
    fn new(stream: Box<dyn Stream>) -> Session {
        Session { stream, pending: Vec::new() }
    }

    async fn command(&mut self, line: &str, name: &str, codes: &[u16]) -> Result<Reply, SmtpError> {
        self.stream.write_all(format!("{line}\r\n").as_bytes()).await.map_err(connection_error)?;
        self.stream.flush().await.map_err(connection_error)?;
        let reply = self.read().await?;
        expect_code(&reply, codes, name)?;
        Ok(reply)
    }

    async fn read(&mut self) -> Result<Reply, SmtpError> {
        let mut lines: Vec<String> = Vec::new();
        let mut size = 0;
        loop {
            while let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
                let raw: Vec<u8> = self.pending.drain(..=end).collect();
                let text: String = raw[..raw.len() - 1].iter().map(|b| *b as char).collect();
                let line = text.strip_suffix('\r').unwrap_or(&text);
                // `^(\d{3})(?:([ -])(.*))?$`
                let b = line.as_bytes();
                let well_formed = b.len() >= 3 && b[..3].iter().all(u8::is_ascii_digit) && (b.len() == 3 || b[3] == b' ' || b[3] == b'-') && !line.contains('\r');
                if !well_formed {
                    return Err(SmtpError("smtp: the server's reply is malformed".into()));
                }
                // The whole reply is capped, continuation lines included: a
                // server can't make the process buffer without bound.
                size += line.len();
                if size > MAX_REPLY_BYTES {
                    return Err(SmtpError("smtp: the server's reply is too long".into()));
                }
                lines.push(line.get(4..).unwrap_or("").to_string());
                if b.get(3) == Some(&b'-') {
                    continue;
                }
                return Ok(Reply { code: line[..3].parse().unwrap_or(0), lines });
            }
            if self.pending.len() > MAX_REPLY_BYTES {
                return Err(SmtpError("smtp: the server's reply is too long".into()));
            }
            let mut buf = [0u8; 4096];
            match self.stream.read(&mut buf).await {
                Ok(0) => return Err(SmtpError("smtp: the server closed the connection".into())),
                Ok(n) => self.pending.extend_from_slice(&buf[..n]),
                Err(e) => return Err(connection_error(e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        for ok in ["alice@example.com", "a.b+c@sub.example.co", "x@1.example"] {
            assert!(is_email_address(ok), "{ok}");
        }
        for bad in ["", "alice", "@example.com", "a@b", "a@@example.com", "a b@example.com", ".a@example.com", "a..b@example.com", "a@example.123", "a@-x.example.com", "\"a\"@example.com"] {
            assert!(!is_email_address(bad), "{bad}");
        }
    }

    #[test]
    fn senders() {
        assert_eq!(parse_from("auth@example.com").ok().unwrap().header, "auth@example.com");
        assert_eq!(parse_from("Example Auth <auth@example.com>").ok().unwrap().header, "Example Auth <auth@example.com>");
        assert_eq!(parse_from("\"Auth, Example\" <auth@example.com>").ok().unwrap().header, "\"Auth, Example\" <auth@example.com>");
        assert_eq!(parse_from("Zo\u{eb} <auth@example.com>").ok().unwrap().header, "=?UTF-8?B?Wm/Dqw==?= <auth@example.com>");
        assert!(parse_from("Auth <not an address>").is_err());
        assert!(parse_from("auth@example.com>").is_err());
    }

    #[test]
    fn smtp_urls() {
        let s = parse_smtp_url("smtps://user:p%40ss@mail.example.com").ok().unwrap();
        assert_eq!((s.host.as_str(), s.port, s.secure), ("mail.example.com", 465, SmtpSecurity::Implicit));
        assert_eq!(s.password.as_deref(), Some("p@ss"));
        assert_eq!(parse_smtp_url("smtp://mail.example.com").ok().unwrap().secure, SmtpSecurity::StartTls);
        assert_eq!(parse_smtp_url("smtp://localhost:2525").ok().unwrap().secure, SmtpSecurity::None);
        assert_eq!(parse_smtp_url("smtp://127.0.0.1:2525").ok().unwrap().secure, SmtpSecurity::None);
        for bad in ["http://mail.example.com", "smtp://mail.example.com/x", "smtp://user@mail.example.com", "smtp://mail.example.com?x=1", "nonsense"] {
            assert!(parse_smtp_url(bad).is_err(), "{bad}");
        }
    }
}
