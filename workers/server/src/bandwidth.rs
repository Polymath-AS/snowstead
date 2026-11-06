//! Import public CDN bytes without replacing the server's origin counters.
use std::collections::HashMap;

use anyhow::{Result, ensure};
use chrono::{Days, NaiveDate, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::AppState;

const ENDPOINT: &str = "https://api.cloudflare.com/client/v4/graphql";
const PAGE: usize = 10_000;
const NAR_BATCH: usize = 1_000;
const MAX_RESPONSE: usize = 16 * 1024 * 1024;
const QUERY: &str = r#"query PublicBandwidth($zoneTag: string!, $host: string!, $date: Date!, $after: string!) {
    viewer { zones(filter: { zoneTag: $zoneTag }) {
        httpRequestsAdaptiveGroups(limit: 10000,
            filter: { date: $date, clientRequestHTTPHost: $host, clientRequestPath_gt: $after },
            orderBy: [clientRequestPath_ASC]) {
            sum { edgeResponseBytes }
            dimensions { clientRequestPath }
        }
    } }
}"#;

#[derive(Deserialize)]
struct GraphResponse {
    data: Option<GraphData>,
    errors: Option<Vec<Value>>,
}

#[derive(Deserialize)]
struct GraphData {
    viewer: Viewer,
}

#[derive(Deserialize)]
struct Viewer {
    zones: Vec<Zone>,
}

#[derive(Deserialize)]
struct Zone {
    #[serde(rename = "httpRequestsAdaptiveGroups")]
    groups: Vec<Group>,
}

#[derive(Deserialize)]
struct Group {
    sum: Sum,
    dimensions: Dimensions,
}

#[derive(Deserialize)]
struct Sum {
    #[serde(rename = "edgeResponseBytes")]
    bytes: f64,
}

#[derive(Deserialize)]
struct Dimensions {
    #[serde(rename = "clientRequestPath")]
    path: String,
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
#[cfg_attr(
    feature = "observability",
    tracing::instrument(
        target = "snowstead_observability",
        skip_all,
        name = "bandwidth.import"
    )
)]
pub(crate) async fn run(state: &AppState) {
    if state.config.analytics_token.is_empty() {
        return;
    }
    let today = Utc::now().date_naive();
    for day in [today - Days::new(1), today] {
        if import_day(state, day, ENDPOINT).await.is_err() {
            // Never log provider responses, SQL parameters, or credentials.
            tracing::warn!(%day, "Public bandwidth import failed; previous counts retained");
        }
    }
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
#[cfg_attr(
    feature = "observability",
    tracing::instrument(
        target = "snowstead_observability",
        skip_all,
        name = "bandwidth.import_day"
    )
)]
async fn import_day(state: &AppState, day: NaiveDate, endpoint: &str) -> Result<()> {
    let origin = reqwest::Url::parse(&state.config.public_cache_origin)?;
    let host = origin
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Missing CDN host"))?;
    let host = origin
        .port()
        .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"));
    let caches = crate::profile_future!(
        sqlx::query!(
            r#"
        SELECT
            c.id,
            c.org_id,
            c.name,
            o.slug,
            o.moving_from
        FROM caches AS c
        JOIN orgs AS o ON o.id = c.org_id
        WHERE c.is_public
        "#,
        )
        .fetch_all(&state.pool),
        label = "bandwidth.caches_sql"
    )
    .await?;
    let mut by_path = HashMap::with_capacity(caches.len() * 2);
    for cache in caches {
        for slug in std::iter::once(cache.slug).chain(cache.moving_from) {
            let path = if slug == "default" {
                cache.name.clone()
            } else {
                format!("{slug}/{}", cache.name)
            };
            by_path.insert(path, (cache.id, cache.org_id.clone()));
        }
    }
    let mut totals: HashMap<(i32, String), f64> = HashMap::new();
    let mut after = String::new();
    loop {
        let mut response = crate::profile_future!(state.http.post(endpoint)
            .bearer_auth(&state.config.analytics_token)
            .json(&json!({"query": QUERY, "variables": {
                "zoneTag": state.config.cdn_zone_id, "host": host, "date": day.to_string(), "after": after,
            }})).send(), label = "bandwidth.analytics_request").await?;
        ensure!(
            response.status().is_success(),
            "CDN analytics request failed"
        );
        let length = response.content_length().unwrap_or(16 * 1024);
        ensure!(
            length <= MAX_RESPONSE as u64,
            "CDN analytics response too large"
        );
        let mut bytes = Vec::with_capacity(length as usize);
        while let Some(chunk) =
            crate::profile_future!(response.chunk(), label = "bandwidth.analytics_body_chunk")
                .await?
        {
            ensure!(
                chunk.len() <= MAX_RESPONSE - bytes.len(),
                "CDN analytics response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        let graph: GraphResponse = serde_json::from_slice(&bytes)?;
        ensure!(
            graph.errors.is_none_or(|errors| errors.is_empty()),
            "CDN analytics query failed"
        );
        let data = graph
            .data
            .ok_or_else(|| anyhow::anyhow!("Missing CDN analytics data"))?;
        ensure!(data.viewer.zones.len() == 1, "Missing CDN analytics zone");
        let groups = data.viewer.zones.into_iter().next().unwrap().groups;
        ensure!(groups.len() <= PAGE, "Invalid CDN analytics page");
        let complete = groups.len() < PAGE;
        let mut nar_bytes = HashMap::with_capacity(groups.len());
        let mut cursor = after.clone();
        for group in groups {
            let path = group.dimensions.path;
            let amount = group.sum.bytes;
            ensure!(
                path > cursor && amount.is_finite() && amount >= 0.0,
                "Invalid CDN analytics group"
            );
            cursor = path.clone();
            let segments: Vec<_> = path.split('/').filter(|s| !s.is_empty()).collect();
            if let ["nar", hash, file] = segments.as_slice()
                && let Some(compression) = file.strip_suffix(".nar")
            {
                nar_bytes.insert(format!("{hash}/{compression}"), amount);
            } else if segments.len() >= 2 {
                let path = if segments[1] == "nix-cache-info"
                    || segments[1] == "nar"
                    || segments[1].ends_with(".narinfo")
                {
                    segments[0].to_owned()
                } else if segments.len() >= 3 {
                    format!("{}/{}", segments[0], segments[1])
                } else {
                    continue;
                };
                if let Some((id, org)) = by_path.get(&path) {
                    *totals.entry((*id, org.clone())).or_default() += amount;
                }
            }
        }
        attribute_nars(&state.pool, nar_bytes, &mut totals).await?;
        if complete {
            break;
        }
        after = cursor;
    }
    // Only a complete successful import may replace a day's public totals.
    // Origin bytes are counted by Rust directly, never overwritten by legacy
    // Analytics Engine snapshots. Cache-zero historical rows stay untouched.
    let mut ids = Vec::with_capacity(totals.len());
    let mut orgs = Vec::with_capacity(totals.len());
    let mut amounts = Vec::with_capacity(totals.len());
    for ((id, org), amount) in totals {
        ensure!(
            amount.is_finite() && amount.round() < i64::MAX as f64,
            "CDN bandwidth exceeds storage range"
        );
        ids.push(id);
        orgs.push(org);
        amounts.push(amount.round() as i64);
    }
    let mut tx =
        crate::profile_future!(state.pool.begin(), label = "bandwidth.import_pool_begin").await?;
    sqlx::query!(
        r#"
        UPDATE bandwidth_daily
        SET public_bytes = 0, imported_at = now()
        WHERE day = $1
          AND cache_id <> 0
        "#,
        day,
    )
    .execute(&mut *tx)
    .await?;
    if !ids.is_empty() {
        sqlx::query!(
            r#"
            INSERT INTO bandwidth_daily (
                org_id, cache_id, product, day, public_bytes, imported_at
            )
            SELECT org, id, 'nix', $1, amount, now()
            FROM unnest($2::text[], $3::int[], $4::bigint[]) AS totals(org, id, amount)
            ON CONFLICT (org_id, cache_id, product, day) DO UPDATE
            SET public_bytes = EXCLUDED.public_bytes,
                imported_at = EXCLUDED.imported_at
            "#,
            day,
            &orgs,
            &ids,
            &amounts,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg_attr(feature = "profiling", hotpath::measure)]
async fn attribute_nars(
    pool: &PgPool,
    bytes: HashMap<String, f64>,
    totals: &mut HashMap<(i32, String), f64>,
) -> Result<()> {
    let nars: Vec<_> = bytes.keys().collect();
    for batch in nars.chunks(NAR_BATCH) {
        let (hashes, compressions): (Vec<_>, Vec<_>) =
            batch.iter().map(|nar| nar.split_once('/').unwrap()).unzip();
        let rows = sqlx::query!(
            r#"
            SELECT DISTINCT
                b.file_hash || '/' || b.compression AS "nar!",
                c.id,
                c.org_id
            FROM blob_objects AS b
            JOIN published_paths AS p ON p.blob_object_id = b.id
            JOIN caches AS c ON c.id = p.cache_id
            WHERE c.is_public
              AND (b.file_hash, b.compression) IN (
                  SELECT * FROM unnest($1::text[], $2::text[])
              )
            "#,
            &hashes as &[&str],
            &compressions as &[&str],
        )
        .fetch_all(pool)
        .await?;
        let mut holders: HashMap<&str, usize> = HashMap::new();
        for row in &rows {
            *holders.entry(&row.nar).or_default() += 1;
        }
        for row in &rows {
            *totals.entry((row.id, row.org_id.clone())).or_default() +=
                bytes[&row.nar] / holders[row.nar.as_str()] as f64;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, storage::Storage};
    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
    };
    use object_store::memory::InMemory;
    use std::{collections::VecDeque, sync::Arc};
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct Provider {
        replies: VecDeque<(StatusCode, Value)>,
        cursors: Vec<String>,
    }

    fn page(paths: impl IntoIterator<Item = (String, u64)>) -> Value {
        let groups: Vec<_> = paths
            .into_iter()
            .map(|(path, bytes)| {
                json!({
                    "dimensions": {"clientRequestPath": path}, "sum": {"edgeResponseBytes": bytes},
                })
            })
            .collect();
        json!({"data": {"viewer": {"zones": [{"httpRequestsAdaptiveGroups": groups}]}}})
    }

    #[sqlx::test(migrator = "crate::migrations::MIGRATOR")]
    #[ignore = "requires disposable Postgres via DATABASE_URL"]
    async fn imports_shared_public_bytes_atomically_without_overwriting_origin_bytes(pool: PgPool) {
        sqlx::raw_sql("INSERT INTO orgs(id,slug,moving_from) VALUES ('alpha','after','before'),('beta','beta',NULL);
            INSERT INTO caches(name,org_id,is_public) VALUES ('main','alpha',true),('main','beta',true),('secret','beta',false),('local','default',true);
            INSERT INTO blob_objects(file_hash,file_size,compression,r2_key) VALUES (repeat('a',64),1,'zstd','nar/shared');
            INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id)
            SELECT c.id,repeat('0',32),'/nix/store/test','sha256:test',1,b.id FROM caches c CROSS JOIN blob_objects b WHERE c.name<>'local';")
            .execute(&pool).await.unwrap();
        let day = NaiveDate::from_ymd_opt(2026, 1, 2).unwrap();
        sqlx::query("INSERT INTO bandwidth_daily(org_id,cache_id,product,day,bytes,public_bytes) SELECT org_id,id,'nix',$1,317,999 FROM caches")
            .bind(day).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO bandwidth_daily(org_id,cache_id,product,day,bytes,public_bytes) VALUES ('default',0,'nix',$1,41,55)")
            .bind(day).execute(&pool).await.unwrap();
        let provider = Arc::new(Mutex::new(Provider::default()));
        let app = Router::new()
            .route(
                "/",
                post(
                    |State(provider): State<Arc<Mutex<Provider>>>,
                     headers: HeaderMap,
                     Json(body): Json<Value>| async move {
                        assert_eq!(headers["authorization"], "Bearer local-test-token");
                        assert_eq!(body["variables"]["host"], "cdn.example.test");
                        assert_eq!(body["variables"]["date"], "2026-01-02");
                        let mut provider = provider.lock().await;
                        provider
                            .cursors
                            .push(body["variables"]["after"].as_str().unwrap().to_owned());
                        let (status, body) = provider
                            .replies
                            .pop_front()
                            .expect("unexpected provider request");
                        (status, Json(body))
                    },
                ),
            )
            .with_state(provider.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let state = AppState::new(
            pool.clone(),
            Config {
                public_cache_origin: "https://cdn.example.test".into(),
                cdn_zone_id: "zone".into(),
                cdn_purge_token: "purge-test-token".into(),
                analytics_token: "local-test-token".into(),
                ..Default::default()
            },
            Storage::from_stores(Arc::new(InMemory::new()), Arc::new(InMemory::new())),
            reqwest::Client::new(),
        )
        .unwrap();
        let paths = vec![
            ("/after/main/nix-cache-info".into(), 13),
            ("/before/main/hash.narinfo".into(), 37),
            ("/beta/main/nix-cache-info".into(), 7),
            ("/beta/secret/nix-cache-info".into(), 900),
            ("/local/nix-cache-info".into(), 11),
            (format!("/nar/{}/zstd.nar", "a".repeat(64)), 201),
            ("/unknown/main/nix-cache-info".into(), 800),
        ];
        for _ in 0..2 {
            provider
                .lock()
                .await
                .replies
                .push_back((StatusCode::OK, page(paths.clone())));
            import_day(&state, day, &endpoint).await.unwrap();
            let rows: Vec<(String, String, i64, i64)> = sqlx::query_as("SELECT c.org_id,c.name,b.bytes,b.public_bytes FROM bandwidth_daily b JOIN caches c ON c.id=b.cache_id WHERE b.day=$1 ORDER BY c.org_id,c.name")
                .bind(day).fetch_all(&pool).await.unwrap();
            assert_eq!(
                rows,
                vec![
                    ("alpha".into(), "main".into(), 317, 151),
                    ("beta".into(), "main".into(), 317, 108),
                    ("beta".into(), "secret".into(), 317, 0),
                    ("default".into(), "local".into(), 317, 11)
                ]
            );
        }
        // A failure in the bulk write must roll back the preceding reset,
        // including timestamps, rather than retaining a partially reset day.
        let before: Vec<String> = sqlx::query_scalar("SELECT row_to_json(b)::text FROM bandwidth_daily b ORDER BY org_id,cache_id,product,day")
            .fetch_all(&pool).await.unwrap();
        sqlx::raw_sql("CREATE FUNCTION reject_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test import failure'; END $$;
            CREATE TRIGGER reject_import BEFORE INSERT ON bandwidth_daily FOR EACH ROW EXECUTE FUNCTION reject_import();")
            .execute(&pool).await.unwrap();
        provider
            .lock()
            .await
            .replies
            .push_back((StatusCode::OK, page(paths.clone())));
        assert!(import_day(&state, day, &endpoint).await.is_err());
        let after: Vec<String> = sqlx::query_scalar("SELECT row_to_json(b)::text FROM bandwidth_daily b ORDER BY org_id,cache_id,product,day")
            .fetch_all(&pool).await.unwrap();
        assert_eq!(after, before);
        sqlx::raw_sql(
            "DROP TRIGGER reject_import ON bandwidth_daily; DROP FUNCTION reject_import();",
        )
        .execute(&pool)
        .await
        .unwrap();
        provider.lock().await.replies.push_back((
            StatusCode::OK,
            page([("/after/main/nix-cache-info".into(), u64::MAX)]),
        ));
        assert!(import_day(&state, day, &endpoint).await.is_err());
        let after: Vec<String> = sqlx::query_scalar("SELECT row_to_json(b)::text FROM bandwidth_daily b ORDER BY org_id,cache_id,product,day")
            .fetch_all(&pool).await.unwrap();
        assert_eq!(after, before);
        // A second-page failure must not reset or partially apply the day.
        let first_page = page((0..PAGE).map(|i| (format!("/unclaimed/{i:05}"), 1)));
        for failure in [
            (StatusCode::SERVICE_UNAVAILABLE, json!({})),
            (
                StatusCode::OK,
                json!({"data":null,"errors":[{"message":"unavailable"}]}),
            ),
        ] {
            provider
                .lock()
                .await
                .replies
                .extend([(StatusCode::OK, first_page.clone()), failure]);
            assert!(import_day(&state, day, &endpoint).await.is_err());
            let total: i64 = sqlx::query_scalar(
                "SELECT sum(public_bytes)::bigint FROM bandwidth_daily WHERE day=$1",
            )
            .bind(day)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(total, 325);
            assert_eq!(
                provider.lock().await.cursors.last().unwrap(),
                "/unclaimed/09999"
            );
        }
        provider
            .lock()
            .await
            .replies
            .push_back((StatusCode::OK, page([])));
        import_day(&state, day, &endpoint).await.unwrap();
        let totals: (i64, i64) = sqlx::query_as(
            "SELECT sum(bytes)::bigint,sum(public_bytes)::bigint FROM bandwidth_daily WHERE day=$1",
        )
        .bind(day)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(totals, (1309, 55));
        server.abort();
        let _ = server.await;
    }
}
