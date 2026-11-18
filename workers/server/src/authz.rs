//! The one authorization decision. Authentication (`auth`) turns a credential
//! into a [`Principal`]; every handler and middleware then asks [`authorize`]
//! whether that principal may perform an [`Action`] on a [`Resource`].
//! Anything the rules below do not allow is denied.
use axum::http::StatusCode;
use chrono::{DateTime, Utc};

pub use snowstead_cache_types::{Access, Permission, Protocol};

use crate::error::ApiError;

/// A cache an API token may use: one cache by ID, or names matching a
/// pattern in which `*` matches any run of characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheGrant {
    Id(i32),
    Pattern(String),
}

#[cfg_attr(feature = "profiling", hotpath::measure_all)]
impl CacheGrant {
    fn matches(&self, id: Option<i32>, name: &str) -> bool {
        match self {
            Self::Id(granted) => id == Some(*granted),
            Self::Pattern(pattern) => matches_pattern(pattern, name),
        }
    }
}

pub(crate) fn matches_pattern(pattern: &str, name: &str) -> bool {
    let Some((first, rest)) = pattern.split_once('*') else {
        return pattern == name;
    };
    let Some(mut remaining) = name.strip_prefix(first) else {
        return false;
    };
    let mut parts = rest.split('*').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            return remaining.ends_with(part);
        }
        let Some(at) = remaining.find(part) else {
            return false;
        };
        remaining = &remaining[at + part.len()..];
    }
    false
}

/// A verified person's role in an organization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Owner,
    Admin,
    Member,
}

impl Role {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            _ => None,
        }
    }

    /// Sensitive organization credentials require ownership.
    fn owns(self) -> bool {
        self == Self::Owner
    }
}

/// A person verified by an embedding application, never by HTTP headers.
#[derive(Clone, Debug)]
pub struct WebUser {
    pub org: String,
    pub user_id: String,
    pub email: String,
    pub role: Role,
}

/// An embedding application's verified identity. Only in-process callers can
/// set request extensions; HTTP headers never construct this value. Normal
/// management policy checks and audit logging still apply.
#[derive(Clone, Debug)]
pub struct TrustedPrincipal(pub Principal);

/// A listed, unrevoked API token with its scope as the database records it.
#[derive(Clone, Debug)]
pub struct ApiToken {
    /// The token's ID, `api_tokens.jti`.
    pub id: String,
    pub org: String,
    pub permissions: Vec<Permission>,
    pub caches: Vec<CacheGrant>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl ApiToken {
    fn allows(&self, permission: Permission, resource: &Resource) -> bool {
        self.permissions.contains(&permission)
            && match resource {
                // Admission for a request that names its cache later; the
                // handler authorizes again against that cache.
                Resource::Org(_) => true,
                Resource::Cache { id, name, .. } => {
                    self.caches.iter().any(|grant| grant.matches(*id, name))
                }
                Resource::Service => false,
            }
    }
}

/// Who is making a request, once authenticated.
#[derive(Clone, Debug)]
pub enum Principal {
    /// The holder of `ADMIN_SECRET`, on the operator surface only.
    Operator,
    WebUser(WebUser),
    ApiToken(ApiToken),
    OrgKey {
        org: String,
        key_id: String,
    },
    /// A self-hosted installation's shared `AUTH_TOKEN`, only when explicitly
    /// enabled. It pushes to the `default` org's caches and nothing else.
    SharedToken,
}

pub(crate) const SHARED_TOKEN_ORG: &str = "default";

#[cfg_attr(feature = "profiling", hotpath::measure_all)]
impl Principal {
    /// The org the principal belongs to; empty for the operator, which
    /// belongs to none and is never authorized for org-scoped protocol work.
    pub fn org(&self) -> &str {
        match self {
            Self::Operator => "",
            Self::WebUser(user) => &user.org,
            Self::ApiToken(token) => &token.org,
            Self::OrgKey { org, .. } => org,
            Self::SharedToken => SHARED_TOKEN_ORG,
        }
    }

    /// Who audit logs and rate limits name.
    pub fn actor(&self) -> String {
        match self {
            Self::Operator => "admin".into(),
            Self::WebUser(user) => format!("user:{}", user.email),
            Self::ApiToken(token) => token.id.clone(),
            Self::OrgKey { key_id, .. } => format!("key:{key_id}"),
            Self::SharedToken => "legacy".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Anything on the operator surface, `/_api/v1/admin`.
    Operate,
    /// Storage limits and plan features, and creating an org.
    OrgLimitsWrite,
    /// The org, its caches, their contents and statistics, pins, eviction.
    OrgRead,
    OrgSlugWrite,
    /// Continue moving caches to the org's new slug.
    OrgMove,
    /// Create, configure, empty, or delete caches and their contents.
    CacheWrite,
    TokenRead,
    /// Create and revoke API tokens.
    TokenWrite,
    ApiKeyRead,
    ApiKeyCreate,
    ApiKeyRevoke,
    SigningKeyRead,
    SigningKeyWrite,
    AuditRead,
    PinWrite,
    /// Read or write a cache through one of its protocols.
    Use(Permission),
}

impl Action {
    const FIXED: [Self; 15] = [
        Self::Operate,
        Self::OrgLimitsWrite,
        Self::OrgRead,
        Self::OrgSlugWrite,
        Self::OrgMove,
        Self::CacheWrite,
        Self::TokenRead,
        Self::TokenWrite,
        Self::ApiKeyRead,
        Self::ApiKeyCreate,
        Self::ApiKeyRevoke,
        Self::SigningKeyRead,
        Self::SigningKeyWrite,
        Self::AuditRead,
        Self::PinWrite,
    ];

    pub const ALL: [Self; Self::FIXED.len() + Permission::ALL.len()] = {
        let mut all = [Self::Operate; Self::FIXED.len() + Permission::ALL.len()];
        let mut i = 0;
        while i < all.len() {
            all[i] = if i < Self::FIXED.len() {
                Self::FIXED[i]
            } else {
                Self::Use(Permission::ALL[i - Self::FIXED.len()])
            };
            i += 1;
        }
        all
    };
}

/// What an action applies to.
#[derive(Clone, Copy, Debug)]
pub enum Resource<'a> {
    /// The service as a whole; only the operator acts on it.
    Service,
    Org(&'a str),
    /// A cache by name, with its ID when it exists.
    Cache {
        org: &'a str,
        id: Option<i32>,
        name: &'a str,
    },
}

impl<'a> Resource<'a> {
    pub fn cache(org: &'a str, id: i32, name: &'a str) -> Self {
        Self::Cache {
            org,
            id: Some(id),
            name,
        }
    }

    fn org(&self) -> Option<&'a str> {
        match *self {
            Self::Service => None,
            Self::Org(org) | Self::Cache { org, .. } => Some(org),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Denied;

impl From<Denied> for ApiError {
    fn from(_: Denied) -> Self {
        ApiError::new(StatusCode::FORBIDDEN, "Forbidden")
    }
}

/// Deny unless a rule below allows `principal` to do `action` on `resource`.
#[cfg_attr(feature = "profiling", hotpath::measure)]
pub fn authorize(principal: &Principal, action: Action, resource: &Resource) -> Result<(), Denied> {
    use Action::*;
    let own = |org: &str| resource.org() == Some(org);
    let allowed = match principal {
        Principal::Operator => match action {
            Operate | OrgLimitsWrite => true,
            OrgRead | OrgSlugWrite | OrgMove | CacheWrite | TokenRead | TokenWrite | ApiKeyRead
            | ApiKeyCreate | ApiKeyRevoke | SigningKeyRead | SigningKeyWrite | AuditRead
            | PinWrite | Use(_) => false,
        },
        Principal::WebUser(user) => {
            own(&user.org)
                && match action {
                    OrgRead | CacheWrite | TokenRead | TokenWrite | ApiKeyRead | SigningKeyRead
                    | AuditRead | PinWrite => true,
                    OrgSlugWrite | OrgMove | ApiKeyCreate | ApiKeyRevoke | SigningKeyWrite => {
                        user.role.owns()
                    }
                    Operate | OrgLimitsWrite | Use(_) => false,
                }
        }
        Principal::OrgKey { org, .. } => {
            own(org)
                && match action {
                    OrgRead | OrgMove | CacheWrite | TokenRead | TokenWrite | ApiKeyRead
                    | ApiKeyRevoke | SigningKeyRead | SigningKeyWrite | AuditRead | PinWrite => {
                        true
                    }
                    Operate | OrgLimitsWrite | OrgSlugWrite | ApiKeyCreate | Use(_) => false,
                }
        }
        Principal::ApiToken(token) => {
            own(&token.org)
                && match action {
                    Use(permission) => token.allows(permission, resource),
                    // Pins name the build a push produced, so pushers may set them.
                    PinWrite => token.allows(Permission::PUSH, resource),
                    Operate | OrgLimitsWrite | OrgRead | OrgSlugWrite | OrgMove | CacheWrite
                    | TokenRead | TokenWrite | ApiKeyRead | ApiKeyCreate | ApiKeyRevoke
                    | SigningKeyRead | SigningKeyWrite | AuditRead => false,
                }
        }
        Principal::SharedToken => match action {
            Use(Permission {
                protocol: Protocol::Nix,
                access: Access::Write,
            }) => own(SHARED_TOKEN_ORG),
            Use(Permission {
                protocol: Protocol::Nix,
                access: Access::Read,
            })
            | Use(Permission {
                protocol: Protocol::Go | Protocol::Sccache | Protocol::Bazel,
                access: Access::Read | Access::Write,
            })
            | Operate
            | OrgLimitsWrite
            | OrgRead
            | OrgSlugWrite
            | OrgMove
            | CacheWrite
            | TokenRead
            | TokenWrite
            | ApiKeyRead
            | ApiKeyCreate
            | ApiKeyRevoke
            | SigningKeyRead
            | SigningKeyWrite
            | AuditRead
            | PinWrite => false,
        },
    };
    if allowed { Ok(()) } else { Err(Denied) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Action::*;

    // Adding an Action without listing it in ALL fails to compile here.
    fn listed(action: Action) -> usize {
        match action {
            Operate => 0,
            OrgLimitsWrite => 1,
            OrgRead => 2,
            OrgSlugWrite => 3,
            OrgMove => 4,
            CacheWrite => 5,
            TokenRead => 6,
            TokenWrite => 7,
            ApiKeyRead => 8,
            ApiKeyCreate => 9,
            ApiKeyRevoke => 10,
            SigningKeyRead => 11,
            SigningKeyWrite => 12,
            AuditRead => 13,
            PinWrite => 14,
            Use(permission) => {
                15 + Permission::ALL
                    .iter()
                    .position(|p| *p == permission)
                    .unwrap()
            }
        }
    }

    #[test]
    fn every_action_is_listed_once() {
        for (index, action) in Action::ALL.into_iter().enumerate() {
            assert_eq!(listed(action), index, "{action:?}");
        }
    }

    fn user(role: Role) -> Principal {
        Principal::WebUser(WebUser {
            org: "org_a".into(),
            user_id: "user_1".into(),
            email: "dev@example.test".into(),
            role,
        })
    }

    fn token(permissions: &[Permission], caches: Vec<CacheGrant>) -> Principal {
        Principal::ApiToken(ApiToken {
            id: "tok".into(),
            org: "org_a".into(),
            permissions: permissions.to_vec(),
            caches,
            expires_at: None,
        })
    }

    const FULL_TOKEN: &[Action] = &[
        Use(Permission::PULL),
        Use(Permission::PUSH),
        PinWrite,
        Use(Protocol::Go.read()),
        Use(Protocol::Go.write()),
        Use(Protocol::Sccache.read()),
        Use(Protocol::Sccache.write()),
        Use(Protocol::Bazel.read()),
        Use(Protocol::Bazel.write()),
    ];
    const GO_TOKEN: &[Action] = &[Use(Protocol::Go.read()), Use(Protocol::Go.write())];
    const SCCACHE_READER: &[Action] = &[Use(Protocol::Sccache.read())];
    const MEMBER: &[Action] = &[
        OrgRead,
        CacheWrite,
        TokenRead,
        TokenWrite,
        ApiKeyRead,
        SigningKeyRead,
        AuditRead,
        PinWrite,
    ];
    const OWNER: &[Action] = &[
        OrgRead,
        CacheWrite,
        TokenRead,
        TokenWrite,
        ApiKeyRead,
        SigningKeyRead,
        AuditRead,
        PinWrite,
        OrgSlugWrite,
        OrgMove,
        ApiKeyCreate,
        ApiKeyRevoke,
        SigningKeyWrite,
    ];
    const ORG_KEY: &[Action] = &[
        OrgRead,
        OrgMove,
        CacheWrite,
        TokenRead,
        TokenWrite,
        ApiKeyRead,
        ApiKeyRevoke,
        SigningKeyRead,
        SigningKeyWrite,
        AuditRead,
        PinWrite,
    ];

    /// For each principal, exactly the actions it may take on its own org's
    /// granted cache `main` (ID 7). Everything else is denied.
    fn table() -> Vec<(&'static str, Principal, &'static [Action])> {
        let all = Permission::ALL.to_vec();
        vec![
            ("operator", Principal::Operator, &[Operate, OrgLimitsWrite]),
            ("owner", user(Role::Owner), OWNER),
            // Ownership is required for sensitive organization credentials.
            ("admin", user(Role::Admin), MEMBER),
            ("member", user(Role::Member), MEMBER),
            (
                "org key",
                Principal::OrgKey {
                    org: "org_a".into(),
                    key_id: "k".into(),
                },
                ORG_KEY,
            ),
            (
                "full token",
                token(&all, vec![CacheGrant::Id(7)]),
                FULL_TOKEN,
            ),
            (
                "pattern pull token",
                token(&[Permission::PULL], vec![CacheGrant::Pattern("ma*".into())]),
                &[Use(Permission::PULL)],
            ),
            (
                "push token",
                token(&[Permission::PUSH], vec![CacheGrant::Id(7)]),
                &[Use(Permission::PUSH), PinWrite],
            ),
            (
                "go token",
                token(
                    &[Protocol::Go.read(), Protocol::Go.write()],
                    vec![CacheGrant::Id(7)],
                ),
                GO_TOKEN,
            ),
            (
                "sccache reader",
                token(&[Protocol::Sccache.read()], vec![CacheGrant::Id(7)]),
                SCCACHE_READER,
            ),
            (
                "token without permissions",
                token(&[], vec![CacheGrant::Id(7)]),
                &[],
            ),
            ("token without caches", token(&all, vec![]), &[]),
            (
                "token for another cache",
                token(
                    &all,
                    vec![CacheGrant::Id(8), CacheGrant::Pattern("other-*".into())],
                ),
                &[],
            ),
            (
                "other org's owner",
                {
                    let Principal::WebUser(mut other) = user(Role::Owner) else {
                        unreachable!()
                    };
                    other.org = "org_b".into();
                    Principal::WebUser(other)
                },
                &[],
            ),
            (
                "other org's key",
                Principal::OrgKey {
                    org: "org_b".into(),
                    key_id: "k".into(),
                },
                &[],
            ),
            // The shared token belongs to the default org only.
            ("shared token", Principal::SharedToken, &[]),
        ]
    }

    #[test]
    fn principal_action_table_on_own_cache() {
        let resource = Resource::cache("org_a", 7, "main");
        for (name, principal, allowed) in table() {
            for action in Action::ALL {
                assert_eq!(
                    authorize(&principal, action, &resource).is_ok(),
                    allowed.contains(&action),
                    "{name} {action:?}"
                );
            }
        }
    }

    #[test]
    fn org_resources_admit_scoped_principals_and_service_admits_only_the_operator() {
        for (name, principal, allowed) in table() {
            for action in Action::ALL {
                let on_org = authorize(&principal, action, &Resource::Org("org_a")).is_ok();
                // Tokens are admitted at org level for actions their
                // permissions cover, whatever their caches; handlers then
                // authorize the named cache.
                let expected = match &principal {
                    Principal::ApiToken(token) => {
                        let required = match action {
                            Use(permission) => Some(permission),
                            PinWrite => Some(Permission::PUSH),
                            Operate | OrgLimitsWrite | OrgRead | OrgSlugWrite | OrgMove
                            | CacheWrite | TokenRead | TokenWrite | ApiKeyRead | ApiKeyCreate
                            | ApiKeyRevoke | SigningKeyRead | SigningKeyWrite | AuditRead => None,
                        };
                        required.is_some_and(|p| token.permissions.contains(&p))
                    }
                    _ => allowed.contains(&action),
                };
                assert_eq!(on_org, expected, "{name} {action:?} on org");
                assert_eq!(
                    authorize(&principal, action, &Resource::Service).is_ok(),
                    matches!(principal, Principal::Operator) && allowed.contains(&action),
                    "{name} {action:?} on service"
                );
            }
        }
    }

    #[test]
    fn scoped_principals_never_reach_another_org() {
        for (name, principal, _) in table() {
            if matches!(principal, Principal::Operator) {
                continue;
            }
            for action in Action::ALL {
                for resource in [Resource::Org("org_c"), Resource::cache("org_c", 7, "main")] {
                    assert!(
                        authorize(&principal, action, &resource).is_err(),
                        "{name} {action:?} {resource:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn shared_token_pushes_only_to_the_default_org() {
        for action in Action::ALL {
            for resource in [
                Resource::Org(SHARED_TOKEN_ORG),
                Resource::cache(SHARED_TOKEN_ORG, 1, "main"),
            ] {
                assert_eq!(
                    authorize(&Principal::SharedToken, action, &resource).is_ok(),
                    action == Use(Permission::PUSH),
                    "{action:?}"
                );
            }
        }
    }

    #[test]
    fn id_grants_need_the_cache_id_and_patterns_match_names() {
        let by_id = token(&[Permission::PULL], vec![CacheGrant::Id(7)]);
        let missing = Resource::Cache {
            org: "org_a",
            id: None,
            name: "main",
        };
        assert!(authorize(&by_id, Use(Permission::PULL), &missing).is_err());
        assert!(
            authorize(
                &by_id,
                Use(Permission::PULL),
                &Resource::cache("org_a", 7, "renamed")
            )
            .is_ok()
        );
        let pattern = token(
            &[Permission::PULL],
            vec![CacheGrant::Pattern("ci-*-release".into())],
        );
        assert!(
            authorize(
                &pattern,
                Use(Permission::PULL),
                &Resource::cache("org_a", 9, "ci-linux-release")
            )
            .is_ok()
        );
        assert!(
            authorize(
                &pattern,
                Use(Permission::PULL),
                &Resource::cache("org_a", 9, "ci-linux-release-extra")
            )
            .is_err()
        );
    }

    #[hegel::test]
    fn cache_patterns_match_a_literal_star_model(tc: hegel::TestCase) {
        use hegel::generators as gs;

        let pattern: String = tc
            .draw(gs::vecs(gs::sampled_from(&['a', 'b', 'é', '.', '[', '*'])).max_size(16))
            .into_iter()
            .collect();
        let name =
            tc.draw(gs::vecs(gs::sampled_from(&['a', 'b', 'é', '.', '[', '*'])).max_size(16));
        // Dynamic programming over Unicode characters, independent of the
        // production matcher's greedy searches over literal substrings.
        let mut matched = vec![false; name.len() + 1];
        matched[0] = true;
        for token in pattern.chars() {
            let mut next = vec![false; name.len() + 1];
            next[0] = token == '*' && matched[0];
            for (i, &letter) in name.iter().enumerate() {
                next[i + 1] = if token == '*' {
                    matched[i + 1] || next[i]
                } else {
                    matched[i] && token == letter
                };
            }
            matched = next;
        }
        assert_eq!(
            matches_pattern(&pattern, &name.iter().collect::<String>()),
            matched[name.len()]
        );
    }
}
