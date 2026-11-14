//! Behaviour every cache protocol shares. Nix, Go, and sccache keep only
//! their wire grammar; names, callers, and request limits are decided here.
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};

use crate::{AppState, auth, authz::Principal, error::ApiError, protocol_policy::CallerLimit};

pub(crate) const SLUG_MAX: usize = 39;
pub(crate) const NAME_MAX: usize = 64;

/// Organization slugs, cache names, and host labels: lowercase letters,
/// digits, and inner dashes.
pub(crate) fn valid_name(name: &str, max: usize) -> bool {
    !name.is_empty()
        && name.len() <= max
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub(crate) fn lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// A lowercase SHA-256 digest, as every protocol addresses content.
pub(crate) fn sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(lower_hex)
}

pub(crate) fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "Not Found")
}

pub(crate) fn method_not_allowed(allow: &'static str) -> ApiError {
    ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
        .header(header::ALLOW, HeaderValue::from_static(allow))
}

/// A declared body size: required, plain decimal, and at most `max`.
pub(crate) fn content_length(headers: &HeaderMap, max: u64) -> Result<u64, ApiError> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| ApiError::new(StatusCode::LENGTH_REQUIRED, "Content-Length required"))?
        .parse::<u64>()
        .ok()
        .filter(|size| *size <= max)
        .ok_or_else(|| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "Artifact is too large"))
}

/// Authenticate a token caller and charge its per-minute budget. This runs
/// before authorization and parsing, so refused requests are also bounded.
pub(crate) async fn caller(
    state: &AppState,
    headers: &HeaderMap,
    limit: CallerLimit,
) -> Result<Principal, ApiError> {
    let principal = auth::authenticate(headers, state).await?;
    state.protocol_limits.check(limit, &principal.actor())?;
    Ok(principal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn length(value: Option<&str>) -> Result<u64, StatusCode> {
        let mut headers = HeaderMap::new();
        if let Some(value) = value {
            headers.insert(header::CONTENT_LENGTH, value.parse().unwrap());
        }
        content_length(&headers, 8).map_err(|error| error.status)
    }

    #[test]
    fn names_digests_and_lengths() {
        for name in ["a", "a-1", "0a"] {
            assert!(valid_name(name, 3), "{name}");
        }
        for name in ["", "-a", "a-", "A", "a_b", "abcd"] {
            assert!(!valid_name(name, 3), "{name}");
        }
        assert!(sha256_hex(&"0f".repeat(32)));
        assert!(!sha256_hex(&"0F".repeat(32)));
        assert!(!sha256_hex(&"0".repeat(63)));
        assert_eq!(length(Some("8")), Ok(8));
        for missing in [None, Some(""), Some("+1"), Some("1.0")] {
            assert_eq!(length(missing), Err(StatusCode::LENGTH_REQUIRED));
        }
        for large in ["9", "18446744073709551616"] {
            assert_eq!(length(Some(large)), Err(StatusCode::PAYLOAD_TOO_LARGE));
        }
    }
}
