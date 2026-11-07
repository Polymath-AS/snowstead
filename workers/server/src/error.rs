use axum::{
    Json,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    pub headers: Box<HeaderMap>,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            headers: Box::default(),
        }
    }

    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        if matches!(error, sqlx::Error::PoolTimedOut)
            || matches!(&error, sqlx::Error::Database(e) if matches!(e.code().as_deref(), Some("55P03" | "40P01" | "40001")))
        {
            return Self::new(StatusCode::SERVICE_UNAVAILABLE, "Database busy; retry").header(
                axum::http::header::RETRY_AFTER,
                HeaderValue::from_static("1"),
            );
        }
        // Do not log connection URLs, SQL parameters, or database messages.
        tracing::error!(
            kind = match error {
                sqlx::Error::PoolTimedOut => "pool_timeout",
                sqlx::Error::PoolClosed => "pool_closed",
                sqlx::Error::Database(_) => "database",
                _ => "database_transport",
            },
            "Database operation failed"
        );
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = json_response(self.status, json!({ "error": self.message }));
        response.headers_mut().extend(*self.headers);
        response
    }
}

pub(crate) fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [
            ("content-type", "application/json; charset=utf-8"),
            ("cache-control", "no-store"),
        ],
        Json(body),
    )
        .into_response()
}
