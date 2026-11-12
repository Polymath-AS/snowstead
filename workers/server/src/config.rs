use std::{net::SocketAddr, time::Duration};

use sqlx::{PgPool, postgres::PgPoolOptions};

/// Secrets deliberately do not implement Debug.
#[derive(Clone, Default)]
pub struct Config {
    /// Verifies JWT-era API tokens that are still listed in `api_tokens`.
    /// Empty rejects every JWT; new tokens are opaque and need no secret.
    pub jwt_secret: String,
    /// A self-hosted installation's shared push token, accepted only when
    /// `ALLOW_SHARED_AUTH_TOKEN=true`. None disables it.
    pub shared_auth_token: Option<String>,
    /// The operator credential, valid only on `/_api/v1/admin`.
    pub admin_secret: String,
    /// Base64 raw Ed25519 public keys, separated by whitespace, that sign the
    /// web's per-request assertions. Empty accepts no dashboard users.
    pub web_assertion_public_keys: String,
    /// Transitional, default off: accept the dashboard's old `ADMIN_SECRET`
    /// calls on org routes (`ALLOW_LEGACY_WEB_ADMIN=true`) during rollout.
    pub allow_legacy_web_admin: bool,
    /// Run without a dashboard and so without assertion keys
    /// (`WEB_ASSERTIONS_DISABLED=true`), as self-hosters may.
    pub web_assertions_disabled: bool,
    /// Accept the local-only dashboard key whose private half is public
    /// (`SNOWSTEAD_LOCAL_DEV_WEB_KEY=true`); only `pnpm dev` sets it.
    pub allow_dev_web_key: bool,
    pub upstreams: Vec<String>,
    pub r2_endpoint: String,
    pub r2_access_key_id: String,
    pub r2_secret_access_key: String,
    pub r2_bucket_name: String,
    pub r2_public_bucket_name: String,
    pub signing_master_key: String,
    pub signing_private_key: String,
    pub signing_key_name: String,
    pub require_cache_signing_keys: bool,
    pub public_url: String,
    pub public_cache_origin: String,
    pub cdn_zone_id: String,
    pub cdn_purge_token: String,
    pub analytics_token: String,
    pub trusted_proxy_ips: String,
    /// Bare DNS suffix for direct organization hosts; empty disables aliases.
    pub cache_host_suffix: String,
    /// Exact canonical DNS hosts inside the suffix, separated by whitespace.
    pub cache_canonical_hosts: String,
    pub resources: ResourceLimits,
    pub push_jobs: PushJobLimits,
}

#[derive(Clone, Debug)]
pub struct PushJobLimits {
    pub members: usize,
    pub chunk_members: usize,
    pub manifest_bytes: usize,
    pub active_per_org: usize,
    /// Reserved by unfinished jobs and retained through completion grace.
    pub protected_members_per_org: usize,
    pub protected_manifest_bytes_per_org: usize,
    /// Opt-in publication of verified job candidates; no transfer scheduling.
    pub publication_workers: usize,
}

impl Default for PushJobLimits {
    fn default() -> Self {
        Self {
            members: 10_000,
            chunk_members: 100,
            manifest_bytes: 16 * 1024 * 1024,
            active_per_org: 4,
            protected_members_per_org: 40_000,
            protected_manifest_bytes_per_org: 64 * 1024 * 1024,
            publication_workers: 0,
        }
    }
}

impl PushJobLimits {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (1..=100_000).contains(&self.members),
            "Invalid PUSH_JOB_MAX_MEMBERS"
        );
        anyhow::ensure!(
            (1..=self.members).contains(&self.chunk_members),
            "Invalid PUSH_JOB_CHUNK_MEMBERS"
        );
        anyhow::ensure!(
            (1..=16 * 1024 * 1024).contains(&self.manifest_bytes),
            "Invalid PUSH_JOB_MANIFEST_BYTES"
        );
        anyhow::ensure!(
            (1..=128).contains(&self.active_per_org),
            "Invalid PUSH_JOB_ACTIVE_PER_ORG"
        );
        anyhow::ensure!(
            (self.members..=12_800_000).contains(&self.protected_members_per_org),
            "Invalid PUSH_JOB_PROTECTED_MEMBERS_PER_ORG"
        );
        anyhow::ensure!(
            (self.manifest_bytes..=2_147_483_648).contains(&self.protected_manifest_bytes_per_org),
            "Invalid PUSH_JOB_PROTECTED_MANIFEST_BYTES_PER_ORG"
        );
        anyhow::ensure!(
            self.publication_workers <= 16,
            "Invalid PUSH_JOB_PUBLICATION_WORKERS"
        );
        Ok(())
    }

    fn from_env() -> Self {
        let read = |name: &str, default| match std::env::var(name) {
            Ok(value) => value.parse().unwrap_or_else(|_| panic!("Invalid {name}")),
            Err(std::env::VarError::NotPresent) => default,
            Err(_) => panic!("Invalid {name}"),
        };
        let defaults = Self::default();
        let limits = Self {
            members: read("PUSH_JOB_MAX_MEMBERS", defaults.members),
            chunk_members: read("PUSH_JOB_CHUNK_MEMBERS", defaults.chunk_members),
            manifest_bytes: read("PUSH_JOB_MANIFEST_BYTES", defaults.manifest_bytes),
            active_per_org: read("PUSH_JOB_ACTIVE_PER_ORG", defaults.active_per_org),
            protected_members_per_org: read(
                "PUSH_JOB_PROTECTED_MEMBERS_PER_ORG",
                defaults.protected_members_per_org,
            ),
            protected_manifest_bytes_per_org: read(
                "PUSH_JOB_PROTECTED_MANIFEST_BYTES_PER_ORG",
                defaults.protected_manifest_bytes_per_org,
            ),
            publication_workers: read("PUSH_JOB_PUBLICATION_WORKERS", defaults.publication_workers),
        };
        limits.validate().expect("Invalid push job limits");
        limits
    }
}

/// Per-process upload memory and verification budgets.
#[derive(Clone, Debug)]
pub struct ResourceLimits {
    pub upload_buffer_mib: usize,
    pub upload_part_mib: usize,
    pub verifications: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            upload_buffer_mib: 1024,
            upload_part_mib: 525,
            verifications: 4,
        }
    }
}

impl ResourceLimits {
    pub fn validate(&self) -> anyhow::Result<()> {
        for (name, value) in [
            ("UPLOAD_BUFFER_MIB", self.upload_buffer_mib),
            ("MAX_UPLOAD_PART_MIB", self.upload_part_mib),
            ("MAX_ACTIVE_VERIFICATIONS", self.verifications),
        ] {
            anyhow::ensure!((1..=65535).contains(&value), "{name} must be in 1..=65535");
        }
        anyhow::ensure!(
            (8..=525).contains(&self.upload_part_mib)
                && self.upload_part_mib <= self.upload_buffer_mib,
            "MAX_UPLOAD_PART_MIB must be in 8..=525 and no larger than UPLOAD_BUFFER_MIB"
        );
        Ok(())
    }

    fn from_env() -> Self {
        fn limit(name: &str, default: usize) -> usize {
            match std::env::var(name) {
                Ok(value) => value
                    .parse()
                    .unwrap_or_else(|_| panic!("{name} must be a positive integer")),
                Err(std::env::VarError::NotPresent) => default,
                Err(_) => panic!("{name} must be a positive integer"),
            }
        }
        let defaults = Self::default();
        let limits = Self {
            upload_buffer_mib: limit("UPLOAD_BUFFER_MIB", defaults.upload_buffer_mib),
            upload_part_mib: limit("MAX_UPLOAD_PART_MIB", defaults.upload_part_mib),
            verifications: limit("MAX_ACTIVE_VERIFICATIONS", defaults.verifications),
        };
        limits.validate().expect("Invalid resource limits");
        limits
    }
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            jwt_secret: std::env::var("JWT_SECRET").unwrap_or_default(),
            shared_auth_token: std::env::var("ALLOW_SHARED_AUTH_TOKEN")
                .is_ok_and(|v| v == "true")
                .then(|| std::env::var("AUTH_TOKEN").unwrap_or_default()),
            admin_secret: std::env::var("ADMIN_SECRET").unwrap_or_default(),
            web_assertion_public_keys: std::env::var("WEB_ASSERTION_PUBLIC_KEYS")
                .unwrap_or_default(),
            allow_legacy_web_admin: std::env::var("ALLOW_LEGACY_WEB_ADMIN")
                .is_ok_and(|v| v == "true"),
            web_assertions_disabled: std::env::var("WEB_ASSERTIONS_DISABLED")
                .is_ok_and(|v| v == "true"),
            allow_dev_web_key: std::env::var("SNOWSTEAD_LOCAL_DEV_WEB_KEY")
                .is_ok_and(|v| v == "true"),
            upstreams: std::env::var("UPSTREAM_CACHES")
                .unwrap_or_default()
                .split_whitespace()
                .map(|url| url.trim_end_matches('/').to_owned())
                .collect(),
            r2_endpoint: std::env::var("R2_ENDPOINT").unwrap_or_default(),
            r2_access_key_id: std::env::var("R2_ACCESS_KEY_ID").unwrap_or_default(),
            r2_secret_access_key: std::env::var("R2_SECRET_ACCESS_KEY").unwrap_or_default(),
            r2_bucket_name: std::env::var("R2_BUCKET_NAME")
                .unwrap_or_else(|_| "snowstead-private".into()),
            r2_public_bucket_name: std::env::var("R2_PUBLIC_BUCKET_NAME")
                .unwrap_or_else(|_| "snowstead-public".into()),
            signing_master_key: std::env::var("SIGNING_MASTER_KEY").unwrap_or_default(),
            signing_private_key: std::env::var("SIGNING_PRIVATE_KEY").unwrap_or_default(),
            signing_key_name: std::env::var("SIGNING_KEY_NAME")
                .unwrap_or_else(|_| "snowstead-1".into()),
            require_cache_signing_keys: std::env::var("REQUIRE_CACHE_SIGNING_KEYS")
                .is_ok_and(|v| v == "true"),
            public_url: std::env::var("PUBLIC_URL").unwrap_or_default(),
            public_cache_origin: std::env::var("PUBLIC_CACHE_ORIGIN").unwrap_or_default(),
            cdn_zone_id: std::env::var("CDN_ZONE_ID").unwrap_or_default(),
            cdn_purge_token: std::env::var("CDN_PURGE_TOKEN").unwrap_or_default(),
            analytics_token: std::env::var("ANALYTICS_TOKEN").unwrap_or_default(),
            trusted_proxy_ips: std::env::var("TRUSTED_PROXY_IPS").unwrap_or_default(),
            cache_host_suffix: std::env::var("CACHE_HOST_SUFFIX").unwrap_or_default(),
            cache_canonical_hosts: std::env::var("CACHE_CANONICAL_HOSTS").unwrap_or_default(),
            resources: ResourceLimits::from_env(),
            push_jobs: PushJobLimits::from_env(),
        }
    }
}

/// Shortest accepted operator and shared-token secrets.
const MIN_SECRET_LEN: usize = 16;

impl Config {
    /// Startup checks for a serving process: refuse to run with credentials
    /// that are missing or malformed, rather than deny every request later.
    pub fn validate_auth(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.admin_secret.len() >= MIN_SECRET_LEN,
            "ADMIN_SECRET must be set, at least {MIN_SECRET_LEN} characters"
        );
        if let Some(token) = &self.shared_auth_token {
            anyhow::ensure!(
                token.len() >= MIN_SECRET_LEN,
                "ALLOW_SHARED_AUTH_TOKEN=true needs AUTH_TOKEN, at least {MIN_SECRET_LEN} characters"
            );
            anyhow::ensure!(
                token != &self.admin_secret,
                "AUTH_TOKEN must differ from ADMIN_SECRET"
            );
        }
        anyhow::ensure!(
            self.jwt_secret != self.admin_secret,
            "JWT_SECRET must differ from ADMIN_SECRET"
        );
        let keys = crate::auth::assertion_keys(&self.web_assertion_public_keys)?;
        anyhow::ensure!(
            !keys.is_empty() || self.allow_legacy_web_admin || self.web_assertions_disabled,
            "WEB_ASSERTION_PUBLIC_KEYS must be set, or WEB_ASSERTIONS_DISABLED=true without a dashboard"
        );
        anyhow::ensure!(
            self.allow_dev_web_key || !keys.contains(&crate::auth::local_dev_web_key()),
            "WEB_ASSERTION_PUBLIC_KEYS contains the published local development key"
        );
        Ok(())
    }
}

pub fn listen_address() -> anyhow::Result<SocketAddr> {
    Ok(std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
        .parse()?)
}

/// Create a bounded pool. Queued requests wait here rather than creating
/// more origin connections. Primary and replica pools have separate limits.
#[cfg_attr(feature = "profiling", hotpath::measure)]
pub async fn connect_pool(
    url: &str,
    max_connections: u32,
    min_connections: u32,
) -> Result<PgPool, sqlx::Error> {
    let options = PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(min_connections.min(max_connections))
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(60));
    #[cfg(feature = "observability")]
    let options = if crate::observability::enabled() {
        options.acquire_time_level(log::LevelFilter::Debug)
    } else {
        options
    };
    options.connect(url).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_configuration_fails_closed_at_startup() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let key = STANDARD.encode(
            ed25519_dalek::SigningKey::from_bytes(&[3; 32])
                .verifying_key()
                .as_bytes(),
        );
        let dev_key = "2aLdazRgIkJp0m0Ik8oS5B0sUJQvwU6jvSaO4wWP/o0=";
        let valid = Config {
            admin_secret: "operator-secret-1234".into(),
            web_assertion_public_keys: key,
            ..Default::default()
        };
        let without_keys = Config {
            web_assertion_public_keys: String::new(),
            ..valid.clone()
        };
        let with_dev_key = Config {
            web_assertion_public_keys: format!("{} {dev_key}", valid.web_assertion_public_keys),
            ..valid.clone()
        };
        for ok in [
            valid.clone(),
            Config {
                allow_legacy_web_admin: true,
                ..without_keys.clone()
            },
            Config {
                web_assertions_disabled: true,
                ..without_keys.clone()
            },
            Config {
                allow_dev_web_key: true,
                ..with_dev_key.clone()
            },
        ] {
            assert!(ok.validate_auth().is_ok());
        }
        for invalid in [
            Config::default(),
            without_keys,
            with_dev_key,
            Config {
                admin_secret: "short".into(),
                ..Default::default()
            },
            Config {
                shared_auth_token: Some(String::new()),
                ..valid.clone()
            },
            Config {
                shared_auth_token: Some(valid.admin_secret.clone()),
                ..valid.clone()
            },
            Config {
                jwt_secret: valid.admin_secret.clone(),
                ..valid.clone()
            },
            Config {
                web_assertion_public_keys: "not-a-key".into(),
                ..valid.clone()
            },
        ] {
            assert!(invalid.validate_auth().is_err());
        }
    }

    #[test]
    fn resource_limits_reject_zero_excessive_and_impossible_budgets() {
        assert!(ResourceLimits::default().validate().is_ok());
        for invalid in [
            ResourceLimits {
                upload_buffer_mib: 0,
                ..Default::default()
            },
            ResourceLimits {
                verifications: 65536,
                ..Default::default()
            },
            ResourceLimits {
                verifications: 0,
                ..Default::default()
            },
            ResourceLimits {
                upload_part_mib: 7,
                ..Default::default()
            },
            ResourceLimits {
                upload_part_mib: 526,
                ..Default::default()
            },
            ResourceLimits {
                upload_buffer_mib: 8,
                upload_part_mib: 16,
                ..Default::default()
            },
        ] {
            assert!(invalid.validate().is_err(), "{invalid:?}");
        }
        assert!(
            ResourceLimits {
                upload_buffer_mib: 32,
                upload_part_mib: 16,
                verifications: 1,
            }
            .validate()
            .is_ok()
        );
    }
}
