//! Dashboard requests: the web signs a short-lived assertion per request with
//! an Ed25519 key whose public half the service is configured with.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signer, SigningKey};

const SEED: [u8; 32] = [42; 32];

/// For `Config::web_assertion_public_keys`.
pub fn public_key() -> String {
    STANDARD.encode(SigningKey::from_bytes(&SEED).verifying_key().as_bytes())
}

/// The bearer credential for `method path` with `body`, as `email` with
/// `role` in `org`.
pub fn assertion(
    method: &str,
    path: &str,
    org: &str,
    role: &str,
    email: &str,
    body: &[u8],
) -> String {
    use sha2::Digest;
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({"aud":"snowstead-cache","org":org,"sub":"user_test","email":email,
        "role":role,"iat":now,"exp":now + 30,"method":method,"path":path,
        "body":hex::encode(sha2::Sha256::digest(body))});
    let signed = format!(
        "snowstead_web.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature = SigningKey::from_bytes(&SEED).sign(signed.as_bytes());
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

/// Where and with what credential a test sends `method path`: org routes go
/// out as the dashboard, signed in as the org's owner (`actor`, by default
/// dev@example.test); org creation and limits go to the operator's
/// `/_api/v1/admin/orgs/{org}`; other routes keep `operator`'s secret.
pub fn dashboard(
    method: &str,
    path: &str,
    operator: &str,
    actor: Option<&str>,
    body: &[u8],
) -> (String, String) {
    let Some(rest) = path.strip_prefix("/_api/v1/orgs/") else {
        return (path.to_owned(), operator.to_owned());
    };
    let org = rest.split(['/', '?']).next().unwrap();
    let route = &rest[org.len()..];
    if method == "PUT" && matches!(route, "" | "/") {
        return (format!("/_api/v1/admin/orgs/{org}"), operator.to_owned());
    }
    let email = actor.unwrap_or("dev@example.test");
    (
        path.to_owned(),
        assertion(method, path, org, "owner", email, body),
    )
}
