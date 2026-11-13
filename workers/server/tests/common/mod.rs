use std::sync::Arc;

use object_store::memory::InMemory;
use snowstead_server::storage::Storage;

#[allow(dead_code)]
pub fn router(state: snowstead_server::AppState) -> axum::Router {
    // The last router clone owns discovery, not a self-retaining worker.
    // Dropping a test host must release its pool before the next SQLx test.
    let stop = Arc::new(state.start_upload_finalizers().drop_guard());
    snowstead_server::router(state).layer(axum::Extension(stop))
}

pub fn storage() -> Storage {
    Storage::from_stores(Arc::new(InMemory::new()), Arc::new(InMemory::new()))
}

#[allow(dead_code)]
pub fn s3_storage() -> Storage {
    let mut config = snowstead_server::config::Config::from_env();
    let endpoint = std::env::var("SNOWSTEAD_TEST_R2_ENDPOINT")
        .expect("run via scripts/with-r2.sh; never use production storage for tests");
    assert!(endpoint.starts_with("http://127.0.0.1:"));
    assert_eq!(config.r2_endpoint, endpoint);
    assert_eq!(config.r2_bucket_name, "snowstead-private");
    assert_eq!(config.r2_public_bucket_name, "snowstead-public");
    // A test database's orphan sweep must never see another test's objects.
    // The disposable MinIO process owns these buckets until the test run ends.
    let id = uuid::Uuid::now_v7();
    config.r2_bucket_name = format!("snowstead-private-{id}");
    config.r2_public_bucket_name = format!("snowstead-public-{id}");
    let mut url = reqwest::Url::parse(&endpoint).unwrap();
    url.set_username(&config.r2_access_key_id).unwrap();
    url.set_password(Some(&config.r2_secret_access_key))
        .unwrap();
    let home = std::env::temp_dir().join(format!("snowstead-test-mc-{id}"));
    std::fs::create_dir(&home).unwrap();
    let created = std::process::Command::new("mc")
        .args(["--config-dir", home.to_str().unwrap(), "mb"])
        .arg(format!("fixture/{}", config.r2_bucket_name))
        .arg(format!("fixture/{}", config.r2_public_bucket_name))
        .env("MC_HOST_fixture", url.as_str())
        .output()
        .unwrap();
    std::fs::remove_dir_all(home).unwrap();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    Storage::new(&config).unwrap()
}
