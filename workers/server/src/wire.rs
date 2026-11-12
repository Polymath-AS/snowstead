//! The CLI wire protocol on the server: protocol-version negotiation, typed
//! JSON responses, and conversions from persisted state into the shared
//! `snowstead-protocol` types.
use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use snowstead_protocol::{
    self as protocol, ProtocolInfo, PushJobMember, SessionStatus, UnsupportedProtocol,
};

use crate::{error::json_response, lifecycle::UploadStatus};

/// A JSON response from a protocol type. It goes through `serde_json::Value`,
/// whose maps sort their keys, so the bytes match what the server sent when
/// it built these bodies with `json!`.
pub(crate) fn respond<T: Serialize>(status: StatusCode, body: &T) -> Response {
    json_response(
        status,
        serde_json::to_value(body).expect("protocol types serialize to JSON"),
    )
}

fn advertise(headers: &mut HeaderMap) {
    headers.insert(
        protocol::PROTOCOL_VERSION_HEADER,
        HeaderValue::from(protocol::PROTOCOL_VERSION),
    );
    headers.insert(
        protocol::MIN_PROTOCOL_VERSION_HEADER,
        HeaderValue::from(protocol::MIN_PROTOCOL_VERSION),
    );
}

/// Refuse a client whose protocol version this server cannot serve, before
/// authentication or parsing. A request without the header comes from a CLI
/// predating versioning and is served as version 1. Every response carries
/// the server's version range so a client can tell which side to upgrade.
pub(crate) async fn negotiate(request: Request, next: Next) -> Response {
    let requested = request
        .headers()
        .get(protocol::PROTOCOL_VERSION_HEADER)
        .map(|value| value.to_str().unwrap_or_default());
    let mut response = match protocol::client_version(requested) {
        Ok(_) => next.run(request).await,
        Err(mismatch) => respond(
            StatusCode::BAD_REQUEST,
            &UnsupportedProtocol {
                error: mismatch.to_string(),
                protocol_version: protocol::PROTOCOL_VERSION,
                min_protocol_version: protocol::MIN_PROTOCOL_VERSION,
            },
        ),
    };
    advertise(response.headers_mut());
    response
}

/// `GET /_api/v1/protocol`: the version range and capabilities, for any
/// client, without credentials.
pub(crate) async fn info() -> Response {
    let mut response = respond(StatusCode::OK, &ProtocolInfo::current());
    advertise(response.headers_mut());
    response
}

/// Read stored JSON as a protocol type, tolerating rows written in another
/// shape: such a value reads as absent instead of failing the request.
pub(crate) fn stored<T: DeserializeOwned>(value: Option<Value>) -> Option<T> {
    value.and_then(|value| serde_json::from_value(value).ok())
}

/// A stored push-job member for a progress page. One that fits the protocol
/// is sent in its typed form; one that does not is passed through unchanged,
/// as the server did before the types existed, so it fails only itself.
pub(crate) fn member(value: Value) -> Value {
    match serde_json::from_value::<PushJobMember>(value.clone()) {
        Ok(member) => serde_json::to_value(member).unwrap_or(value),
        Err(_) => value,
    }
}

impl From<UploadStatus> for SessionStatus {
    fn from(status: UploadStatus) -> Self {
        match status {
            UploadStatus::LegacyPending => Self::LegacyPending,
            UploadStatus::LegacyUploading => Self::LegacyUploading,
            UploadStatus::LegacyCompleting => Self::LegacyCompleting,
            UploadStatus::Streaming => Self::Streaming,
            UploadStatus::Finalizing => Self::Finalizing,
            UploadStatus::Completed => Self::Completed,
            UploadStatus::Aborted => Self::Aborted,
            UploadStatus::Expired => Self::Expired,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, middleware, routing::get};
    use tower::ServiceExt;

    #[test]
    fn off_shape_stored_rows_degrade_without_failing_the_request() {
        use serde_json::json;
        use snowstead_protocol::{Receipt, UploadResult};
        // A receipt missing its parts, and a result whose status is text.
        let receipt = json!({"sessionId":"s","narHash":"sha256:n","narSize":1});
        assert_eq!(stored::<Receipt>(Some(receipt)), None);
        let result = json!({"sessionId":"s","published":true,"status":"done"});
        assert_eq!(stored::<UploadResult>(Some(result)), None);
        let good = json!({"sessionId":"s","storePathHash":"h","published":true});
        assert_eq!(
            stored::<UploadResult>(Some(good)),
            Some(UploadResult::published("s", "h"))
        );
        assert_eq!(stored::<UploadResult>(None), None);

        let typed = json!({"storePath":"/nix/store/h-x","storePathHash":"h","narHash":"sha256:n",
            "narSize":1,"compression":"zstd","references":[],"deriver":null,"inline":false,
            "available":true,"session":null});
        assert_eq!(member(typed.clone()), typed);
        // A member whose stored session result is off-shape passes through
        // exactly as stored, so the page still renders.
        let mut odd = typed;
        odd["narSize"] = json!(-1);
        odd["session"] = json!({"sessionId":"s","status":"finalizing","prepared":true,
            "publicationResult":"legacy text"});
        assert_eq!(member(odd.clone()), odd);
    }

    #[test]
    fn session_statuses_keep_their_column_text() {
        for status in UploadStatus::ALL {
            assert_eq!(
                serde_json::to_value(SessionStatus::from(*status)).unwrap(),
                status.as_str()
            );
        }
    }

    #[tokio::test]
    async fn versions_are_negotiated_before_handlers_run() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .route_layer(middleware::from_fn(negotiate));
        let send = |version: Option<&str>| {
            let mut request = Request::builder().uri("/");
            if let Some(version) = version {
                request = request.header(protocol::PROTOCOL_VERSION_HEADER, version);
            }
            app.clone().oneshot(request.body(Body::empty()).unwrap())
        };
        for version in [None, Some("1")] {
            let response = send(version).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[protocol::PROTOCOL_VERSION_HEADER], "1");
            assert_eq!(
                response.headers()[protocol::MIN_PROTOCOL_VERSION_HEADER],
                "1"
            );
        }
        for (version, message) in [
            ("0", "Upgrade the Snowstead CLI"),
            ("2", "server is too old"),
            ("one", "invalid Snowstead protocol version"),
        ] {
            let response = send(Some(version)).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response.headers()[protocol::PROTOCOL_VERSION_HEADER], "1");
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let body: UnsupportedProtocol = serde_json::from_slice(&body).unwrap();
            assert!(body.error.contains(message), "{}", body.error);
            assert_eq!((body.protocol_version, body.min_protocol_version), (1, 1));
        }
    }
}
