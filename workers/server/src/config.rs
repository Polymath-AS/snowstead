use std::{net::SocketAddr, time::Duration};

use sqlx::{PgPool, postgres::PgPoolOptions};

/// Secrets deliberately do not implement Debug.
#[derive(Clone, Default)]
pub struct Config {
    pub jwt_secret: String,
    pub auth_token: String,
    pub admin_secret: String,
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
            auth_token: std::env::var("AUTH_TOKEN").unwrap_or_default(),
            admin_secret: std::env::var("ADMIN_SECRET").unwrap_or_default(),
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
        }
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
pub async fn connect_pool(url: &str, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    let options = PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(0)
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
