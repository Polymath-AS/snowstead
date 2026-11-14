//! In-process embedding identities. No test credential is decoded from HTTP.
use axum::http::request::Builder;
use snowstead_server::authz::{Principal, Role, TrustedPrincipal, WebUser};

pub enum Credential {
    Bearer(String),
    Trusted(TrustedPrincipal),
}

impl Credential {
    pub fn apply(self, request: Builder) -> Builder {
        match self {
            Self::Bearer(token) => request.header("authorization", format!("Bearer {token}")),
            Self::Trusted(principal) => request.extension(principal),
        }
    }
}

pub fn person(org: &str, role: Role, email: &str) -> TrustedPrincipal {
    TrustedPrincipal(Principal::WebUser(WebUser {
        org: org.into(),
        user_id: "user_test".into(),
        email: email.into(),
        role,
    }))
}

/// Org creation/limits use the operator surface; other management requests
/// enter as a verified organization owner through an in-process extension.
pub fn dashboard(
    method: &str,
    path: &str,
    operator: &str,
    actor: Option<&str>,
) -> (String, Credential) {
    let Some(rest) = path.strip_prefix("/_api/v1/orgs/") else {
        return (path.into(), Credential::Bearer(operator.into()));
    };
    let org = rest.split(['/', '?']).next().unwrap();
    let route = &rest[org.len()..];
    if method == "PUT" && matches!(route, "" | "/") {
        return (
            format!("/_api/v1/admin/orgs/{org}"),
            Credential::Bearer(operator.into()),
        );
    }
    (
        path.into(),
        Credential::Trusted(person(
            org,
            Role::Owner,
            actor.unwrap_or("dev@example.test"),
        )),
    )
}
