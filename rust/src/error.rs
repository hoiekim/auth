//! How a request fails: a refusal a handler chose, in the one error shape of
//! docs/DESIGN.md §7.7, or anything else, which becomes a 500 and is logged
//! by a name only.

use crate::http::{error_response, Response};

/// A refusal a handler raises; the router turns it into the error response.
#[derive(Debug, Clone)]
pub struct HttpError {
    pub status: u16,
    pub code: &'static str,
    pub description: String,
    pub headers: Vec<(String, String)>,
}

impl HttpError {
    pub fn new(status: u16, code: &'static str, description: impl Into<String>) -> HttpError {
        HttpError { status, code, description: description.into(), headers: Vec::new() }
    }

    pub fn with(status: u16, code: &'static str, description: impl Into<String>, headers: Vec<(String, String)>) -> HttpError {
        HttpError { status, code, description: description.into(), headers }
    }

    pub fn response(&self) -> Response {
        error_response(self.status, self.code, &self.description, &self.headers)
    }
}

#[derive(Debug)]
pub enum Error {
    Http(HttpError),
    Db(tokio_postgres::Error),
    Pool,
    /// A signing key whose stored public half can't be used, by its kid
    /// (which is public).
    UnreadableKey(String),
    /// Anything else, by the name it is logged under.
    Other(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// The name a log line carries. Never the message: it can quote a query,
    /// a token or a connection string (§9.3).
    pub fn name(&self) -> &'static str {
        match self {
            Error::Http(_) => "HttpError",
            Error::Db(_) => "PostgresError",
            Error::Pool => "PoolError",
            Error::UnreadableKey(_) => "UnreadableKeyError",
            Error::Other(name) => name,
        }
    }

    /// A unique-constraint violation, optionally of one constraint.
    pub fn is_unique_violation(&self, constraint: Option<&str>) -> bool {
        let Error::Db(e) = self else { return false };
        let Some(db) = e.as_db_error() else { return false };
        db.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION && constraint.is_none_or(|c| db.constraint() == Some(c))
    }

    pub fn http_status(&self) -> Option<u16> {
        match self {
            Error::Http(e) => Some(e.status),
            _ => None,
        }
    }
}

impl From<HttpError> for Error {
    fn from(e: HttpError) -> Error {
        Error::Http(e)
    }
}

impl From<tokio_postgres::Error> for Error {
    fn from(e: tokio_postgres::Error) -> Error {
        Error::Db(e)
    }
}

impl From<deadpool_postgres::PoolError> for Error {
    fn from(e: deadpool_postgres::PoolError) -> Error {
        match e {
            deadpool_postgres::PoolError::Backend(e) => Error::Db(e),
            _ => Error::Pool,
        }
    }
}

/// `throw new HttpError(...)`.
macro_rules! bail {
    ($status:expr, $code:expr, $($arg:tt)*) => {
        return Err($crate::error::Error::Http($crate::error::HttpError::new($status, $code, format!($($arg)*))))
    };
}
pub(crate) use bail;

pub fn http(status: u16, code: &'static str, description: impl Into<String>) -> Error {
    Error::Http(HttpError::new(status, code, description))
}
