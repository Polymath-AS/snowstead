mod common;

#[path = "support/web.rs"]
mod web;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use serde_json::{Value, json};
use snowstead_server::{AppState, config::Config, router, storage::Storage};
use sqlx::PgPool;
use tower::ServiceExt;

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    input: Value,
    actor: Option<&str>,
) -> (StatusCode, HeaderMap, Value) {
    let (path, credential) = web::dashboard(
        method,
        path,
        "operator",
        actor,
        input.to_string().as_bytes(),
    );
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {credential}"))
        .header("content-type", "application/json");
    let response = app
        .clone()
        .oneshot(request.body(Body::from(input.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let value =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)));
    (status, headers, value)
}

fn state(pool: PgPool) -> AppState {
    state_with_storage(pool, common::storage())
}

fn state_with_storage(pool: PgPool, storage: Storage) -> AppState {
    AppState::new(
        pool,
        Config {
            admin_secret: "operator".into(),
            web_assertion_public_keys: web::public_key(),
            jwt_secret: "jwt-secret".into(),
            ..Default::default()
        },
        storage,
        reqwest::Client::new(),
    )
    .unwrap()
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn org_settings_inventory_and_cache_contract(pool: PgPool) {
    let app = router(state(pool.clone()));
    let base = "/_api/v1/orgs/org_alpha";
    let (status, _, created) = call(
        &app,
        "PUT",
        base,
        json!({"slug":"alpha","storageLimit":321,"privateCaches":false}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(
        created,
        json!({"id":"org_alpha","slug":"alpha","movingFrom":null,"storageLimit":321,"privateCaches":false,"customSigningKeys":false,"used":0,"pending":0,"servedThisMonth":0,"publicServedThisMonth":0,"servedThisMonthByProduct":{"nix":0,"go":0,"sccache":0},"bandwidthUpdatedAt":null})
    );
    assert_eq!(
        call(&app, "PUT", base, json!({"slug":"alpha"}), None)
            .await
            .2,
        created
    );
    assert_eq!(
        call(&app, "GET", &format!("{base}/"), Value::Null, None)
            .await
            .2,
        created
    );
    for input in [
        json!({"storageLimit":-1}),
        json!({"storageLimit":0.5}),
        json!({"privateCaches":null}),
        json!({"customSigningKeys":null}),
        json!({"slug":null}),
        json!({"unexpected":true}),
    ] {
        assert_eq!(
            call(&app, "PUT", base, input, None).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    let (_, _, updated) = call(
        &app,
        "PUT",
        base,
        json!({"storageLimit":null,"customSigningKeys":true}),
        None,
    )
    .await;
    assert!(updated["storageLimit"].is_null());
    assert_eq!(updated["privateCaches"], false);
    assert_eq!(updated["customSigningKeys"], true);
    for path in [format!("{base}/caches"), "/_api/v1/admin/caches".into()] {
        for org in [json!(null), json!(42), json!("invalid/org")] {
            assert_eq!(
                call(
                    &app,
                    "POST",
                    &path,
                    json!({"name":"invalid-org","org":org,"protocols":["nix"]}),
                    None,
                )
                .await
                .0,
                StatusCode::BAD_REQUEST
            );
        }
    }
    assert_eq!(
        call(
            &app,
            "PUT",
            "/_api/v1/orgs/default",
            json!({"slug":"elsewhere"}),
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("{base}/caches"),
            json!({"name":"main","protocols":["nix"],"private":true}),
            None
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, _, cache) = call(
        &app,
        "POST",
        &format!("{base}/caches"),
        json!({"name":"main","protocols":["nix"],"retentionDays":9}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{cache}");
    assert_eq!(cache["path"], "alpha/main");
    assert_eq!(cache["created"], true);
    assert_eq!(cache["changed"], false);
    let (status, _, repeat) = call(
        &app,
        "POST",
        &format!("{base}/caches"),
        json!({"name":"main"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(repeat["retentionDays"], 9);
    assert_eq!(repeat["created"], false);
    assert_eq!(repeat["changed"], false);
    let (status, _, floating) = call(
        &app,
        "POST",
        &format!("{base}/caches"),
        json!({"name":"main","retentionDays":3.0}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(floating["retentionDays"], 3);
    let (_, _, added) = call(
        &app,
        "POST",
        &format!("{base}/caches"),
        json!({"name":"main","protocols":["nix","go"],"retentionDays":null}),
        None,
    )
    .await;
    assert_eq!(added["changed"], true);
    assert!(added["retentionDays"].is_null());
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("{base}/caches"),
            json!({"name":"main","protocols":["go"]}),
            None
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (_, _, detail) = call(
        &app,
        "GET",
        &format!("{base}/caches/main"),
        Value::Null,
        None,
    )
    .await;
    assert_eq!(detail["protocols"], json!(["nix", "go"]));
    assert_eq!(detail["paths"], 0);
    assert_eq!(detail["size"], 0);
    assert!(detail["publicKey"].is_null());
    assert_eq!(detail["recentPaths"], json!([]));
    assert!(detail["createdAt"].as_str().unwrap().ends_with('Z'));
    let (status, _, added) = call(
        &app,
        "POST",
        &format!("{base}/caches"),
        json!({"name":"main","protocols":["sccache","nix","go"]}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{added}");
    assert_eq!(added["changed"], true);
    let (_, _, repeat) = call(
        &app,
        "POST",
        &format!("{base}/caches"),
        json!({"name":"main"}),
        None,
    )
    .await;
    assert_eq!(repeat["protocols"], json!(["sccache", "nix", "go"]));
    assert_eq!(repeat["changed"], false);
    let (status, _, inventory) = call(
        &app,
        "GET",
        "/_api/v1/admin/orgs?id=org_alpha&id=not_found",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inventory["orgs"].as_array().unwrap().len(), 1);
    for query in [
        "?",
        "?org=org_alpha",
        "?id=",
        "?id=org_alpha&",
        "?id=org_alpha&&id=default",
    ] {
        assert_eq!(
            call(
                &app,
                "GET",
                &format!("/_api/v1/admin/orgs{query}"),
                Value::Null,
                None
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    let (status, _, overview) =
        call(&app, "GET", "/_api/v1/admin/overview", Value::Null, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(overview["orgs"], 2);
    assert_eq!(overview["caches"], 1);
    assert_eq!(overview["paths"], 0);
    let (_, _, audit) = call(&app, "GET", &format!("{base}/audit"), Value::Null, None).await;
    let changes = audit["entries"].as_array().unwrap();
    assert!(changes.iter().any(|r| r["action"] == "org.put"
        && r["detail"]["old"]["storageLimit"] == 321
        && r["detail"]["new"]["storageLimit"].is_null()));
    assert_eq!(
        call(&app, "PUT", "/_api/v1/admin/", json!({}), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn only_global_overview_uses_the_read_pool(pool: PgPool) {
    // Independent data models replica lag without a physical standby.
    sqlx::raw_sql(
        "CREATE SCHEMA replica;
        CREATE TABLE replica.orgs (LIKE public.orgs INCLUDING ALL);
        CREATE TABLE replica.caches (LIKE public.caches INCLUDING ALL);
        CREATE TABLE replica.blob_objects (LIKE public.blob_objects INCLUDING ALL);
        CREATE TABLE replica.upload_sessions (LIKE public.upload_sessions INCLUDING ALL);
        CREATE TABLE replica.bandwidth_daily (LIKE public.bandwidth_daily INCLUDING ALL);
        CREATE TABLE replica.api_tokens (LIKE public.api_tokens INCLUDING ALL);
        CREATE TABLE replica.org_api_keys (LIKE public.org_api_keys INCLUDING ALL);
        INSERT INTO replica.orgs(id,slug) VALUES ('old_alpha','old-alpha'),('old_beta','old-beta');
        INSERT INTO replica.caches(name,org_id,path_count,size) VALUES ('old','old_alpha',3,17);",
    )
    .execute(&pool)
    .await
    .unwrap();
    let read_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone().options([
            ("search_path", "replica"),
            ("default_transaction_read_only", "on"),
        ]))
        .await
        .unwrap();
    let mut state = state(pool.clone());
    state.read_pool = read_pool.clone();
    let app = router(state);
    let (status, _, overview) =
        call(&app, "GET", "/_api/v1/admin/overview", Value::Null, None).await;
    assert_eq!(status, StatusCode::OK, "{overview}");
    assert_eq!(
        overview,
        json!({"orgs":2,"caches":1,"paths":3,"storedBytes":17,
            "physicalStoredBytes":0,"pendingBytes":0,"uploadsPending":0,
            "servedThisMonth":0,"publicServedThisMonth":0,"activeTokens":0,"apiKeys":0})
    );

    let (status, _, created) = call(
        &app,
        "PUT",
        "/_api/v1/orgs/fresh",
        json!({"slug":"fresh","storageLimit":123}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["storageLimit"], 123);
    let (status, _, fetched) = call(&app, "GET", "/_api/v1/orgs/fresh", Value::Null, None).await;
    assert_eq!(status, StatusCode::OK, "{fetched}");
    assert_eq!(fetched, created);
    assert_eq!(
        call(&app, "GET", "/_api/v1/admin/overview", Value::Null, None)
            .await
            .2,
        overview
    );

    // Replica failure must not silently route the overview back to primary.
    read_pool.close().await;
    assert_eq!(
        call(&app, "GET", "/_api/v1/admin/overview", Value::Null, None)
            .await
            .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        call(&app, "GET", "/_api/v1/orgs/fresh", Value::Null, None)
            .await
            .2,
        created
    );
    assert_eq!(
        call(&app, "GET", "/healthz", Value::Null, None).await.0,
        StatusCode::OK
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn blocked_policy_update_does_not_block_another_org_slug_claim(pool: PgPool) {
    sqlx::query("INSERT INTO orgs (id,slug) VALUES ('org_alpha','alpha')")
        .execute(&pool)
        .await
        .unwrap();
    let app = router(state(pool.clone()));
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('org:org_alpha',0))")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let (status, _, _) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        call(
            &app,
            "PUT",
            "/_api/v1/orgs/org_alpha",
            json!({"storageLimit":123}),
            None,
        ),
    )
    .await
    .expect("policy update must fail fast on org A");
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, _, claimed) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        call(
            &app,
            "PUT",
            "/_api/v1/orgs/org_beta",
            json!({"slug":"beta"}),
            None,
        ),
    )
    .await
    .expect("org B's slug claim must not wait for org A's policy update");
    assert_eq!(status, StatusCode::OK, "{claimed}");
    blocker.rollback().await.unwrap();
    let (status, _, updated) = call(
        &app,
        "PUT",
        "/_api/v1/orgs/org_alpha",
        json!({"storageLimit":123}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["storageLimit"], 123);
    assert_eq!(updated["slug"], "alpha");
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn visibility_conflicts_keep_precedence_and_include_unfinished_live_entries(pool: PgPool) {
    sqlx::raw_sql("INSERT INTO caches (name,org_id) VALUES ('main','default');
        INSERT INTO cache_protocols (cache_id,protocol) SELECT id,p FROM caches CROSS JOIN unnest(ARRAY['nix','go','sccache']) p;
        INSERT INTO blob_objects (file_hash,file_size,compression,r2_key) VALUES (repeat('a',64),5,'none','nar/test');
        INSERT INTO published_paths (cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id)
            SELECT c.id,repeat('0',32),'/nix/store/example','sha256:test',5,b.id FROM caches c CROSS JOIN blob_objects b;
        INSERT INTO go_entries (id,cache_id,generation,action,r2_key,size,output,expires_at)
            SELECT 'go'||n,c.id,CASE WHEN n=2 THEN 'old' ELSE '0' END,repeat(n::text,64),'go/'||n,5,repeat('f',64),
                now()+CASE WHEN n=3 THEN -interval '1 day' ELSE interval '1 day' END FROM caches c CROSS JOIN generate_series(1,3) n;
        INSERT INTO sccache_entries (id,cache_id,generation,action,r2_key,size,expires_at)
            SELECT 'sc'||n,c.id,CASE WHEN n=2 THEN 'old' ELSE '0' END,repeat(n::text,64),'sc/'||n,5,
                now()+CASE WHEN n=3 THEN -interval '1 day' ELSE interval '1 day' END FROM caches c CROSS JOIN generate_series(1,3) n;")
        .execute(&pool).await.unwrap();
    let app = router(state(pool.clone()));
    for (message, cleanup) in [
        (
            "only a cache without published paths can change visibility",
            "DELETE FROM published_paths",
        ),
        (
            "only a cache without Go entries or uploads can change visibility; reset Go data first",
            "DELETE FROM go_entries WHERE id='go1'",
        ),
        (
            "only a cache without sccache entries or uploads can change visibility; reset sccache data first",
            "DELETE FROM sccache_entries WHERE id='sc1'",
        ),
    ] {
        let (status, _, response) = call(
            &app,
            "POST",
            "/_api/v1/orgs/default/caches",
            json!({"name":"main","private":true}),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{response}");
        assert_eq!(response, json!({"error":message}));
        sqlx::query(cleanup).execute(&pool).await.unwrap();
    }
    // Expired entries and entries from old generations do not block a change.
    let (status, _, response) = call(
        &app,
        "POST",
        "/_api/v1/orgs/default/caches",
        json!({"name":"main","private":true}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["private"], true);
    assert_eq!(response["changed"], true);
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn overview_counts_live_products_without_join_multiplication(pool: PgPool) {
    let app = router(state(pool.clone()));
    sqlx::raw_sql("INSERT INTO orgs (id,slug) VALUES ('org_alpha','alpha'),('org_beta','beta');
        INSERT INTO caches (name,org_id) VALUES ('main','org_alpha'),('other','org_beta');
        INSERT INTO cache_protocols (cache_id,protocol) SELECT id,p FROM caches CROSS JOIN unnest(ARRAY['nix','go','sccache']) p;
        INSERT INTO blob_objects (file_hash,file_size,compression,r2_key) VALUES (repeat('a',64),13,'none','nar/test');
        INSERT INTO published_paths (cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id)
            SELECT c.id,repeat('0',32),'/nix/store/example','sha256:test',31,b.id FROM caches c CROSS JOIN blob_objects b WHERE c.org_id='org_alpha';
        INSERT INTO go_entries (id,cache_id,generation,action,r2_key,size,output,uploaded_at,expires_at)
            SELECT 'go'||n,c.id,CASE WHEN n=3 THEN 'old' ELSE '0' END,repeat(n::text,64),'go/'||n,CASE n WHEN 1 THEN 17 ELSE 19 END,repeat('f',64),CASE WHEN n=2 THEN NULL ELSE now() END,now()+interval '1 day' FROM caches c CROSS JOIN generate_series(1,3) n WHERE c.org_id='org_alpha';
        INSERT INTO sccache_entries (id,cache_id,generation,action,r2_key,size,uploaded_at,expires_at)
            SELECT 'sc'||n,c.id,'0',repeat(n::text,64),'sccache/'||n,CASE n WHEN 1 THEN 23 ELSE 29 END,CASE WHEN n=2 THEN NULL ELSE now() END,now()+CASE WHEN n=3 THEN -interval '1 second' ELSE interval '1 day' END FROM caches c CROSS JOIN generate_series(1,3) n WHERE c.org_id='org_alpha';
        INSERT INTO bandwidth_daily (org_id,cache_id,product,day,bytes,public_bytes) SELECT c.org_id,c.id,'nix',(now() AT TIME ZONE 'UTC')::date,37,41 FROM caches c WHERE c.org_id='org_alpha';
        INSERT INTO bandwidth_daily (org_id,cache_id,product,day,bytes,public_bytes) SELECT c.org_id,c.id,'go',(now() AT TIME ZONE 'UTC')::date,43,0 FROM caches c WHERE c.org_id='org_alpha';
        INSERT INTO bandwidth_daily (org_id,cache_id,product,day,bytes) SELECT c.org_id,c.id,'sccache',(now() AT TIME ZONE 'UTC')::date,999 FROM caches c WHERE c.org_id='org_beta';")
        .execute(&pool).await.unwrap();
    let (status, _, overview) = call(
        &app,
        "GET",
        "/_api/v1/orgs/org_alpha/overview",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{overview}");
    assert_eq!(overview["used"], 53);
    assert_eq!(overview["pending"], 48);
    assert_eq!(overview["servedThisMonth"], 80);
    assert_eq!(overview["publicServedThisMonth"], 41);
    assert_eq!(
        overview["servedThisMonthByProduct"],
        json!({"nix":78,"go":43,"sccache":0})
    );
    assert_eq!(overview["caches"].as_array().unwrap().len(), 1);
    let cache = &overview["caches"][0];
    assert_eq!(cache["paths"], 1);
    assert_eq!(cache["size"], 13);
    assert_eq!(cache["addedLastWeek"], 1);
    assert_eq!(cache["servedThisMonth"], 80);
    let (_, _, listed) = call(
        &app,
        "GET",
        "/_api/v1/admin/caches?org=org_alpha",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(listed["caches"], overview["caches"]);
    let (_, _, detail) = call(
        &app,
        "GET",
        "/_api/v1/orgs/org_alpha/caches/main",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(detail["recentPaths"][0]["size"], 13);
    assert!(
        detail["recentPaths"][0]["addedAt"]
            .as_str()
            .unwrap()
            .ends_with('Z')
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn cache_summaries_keep_monthly_products_and_paths_separate(pool: PgPool) {
    let app = router(state(pool.clone()));
    sqlx::raw_sql("INSERT INTO orgs(id,slug) VALUES ('org_alpha','alpha'),('org_beta','beta');
        INSERT INTO caches(name,org_id) VALUES ('zeta','org_alpha'),('empty','org_alpha'),('main','org_alpha'),('main','org_beta');
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches;
        INSERT INTO blob_objects(file_hash,file_size,compression,r2_key) VALUES (repeat('a',64),13,'none','nar/test');
        INSERT INTO published_paths(cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id)
            SELECT c.id,repeat(n::text,32),'/nix/store/example-'||n,'sha256:test',31,b.id
            FROM caches c CROSS JOIN blob_objects b CROSS JOIN generate_series(1,2) n WHERE c.org_id='org_alpha' AND c.name='main';
        INSERT INTO bandwidth_daily(org_id,cache_id,product,day,bytes,public_bytes)
            SELECT c.org_id,c.id,v.product,date_trunc('month',now() AT TIME ZONE 'UTC')::date+v.offset_days,v.origin,v.public
            FROM caches c JOIN (VALUES ('org_alpha','main','nix',0,11,17),('org_alpha','main','nix',1,23,29),
                ('org_alpha','main','go',0,31,37),('org_alpha','main','sccache',0,41,43),
                ('org_alpha','zeta','go',0,101,103),('org_beta','main','nix',0,1009,1013),
                ('org_alpha','empty','nix',-1,9999,9999)) AS v(org,name,product,offset_days,origin,public)
                ON c.org_id=v.org AND c.name=v.name;")
        .execute(&pool).await.unwrap();
    let (status, _, listed) = call(
        &app,
        "GET",
        "/_api/v1/admin/caches?org=org_alpha",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let caches = listed["caches"].as_array().unwrap();
    assert_eq!(
        caches
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["empty", "main", "zeta"]
    );
    for (cache, origin, public, products, paths) in [
        (&caches[0], 0, 0, json!({"nix":0,"go":0,"sccache":0}), 0),
        (
            &caches[1],
            106,
            126,
            json!({"nix":80,"go":68,"sccache":84}),
            2,
        ),
        (
            &caches[2],
            101,
            103,
            json!({"nix":0,"go":204,"sccache":0}),
            0,
        ),
    ] {
        assert_eq!(cache["servedThisMonth"], origin);
        assert_eq!(cache["publicServedThisMonth"], public);
        assert_eq!(cache["servedThisMonthByProduct"], products);
        assert_eq!(cache["paths"], paths);
        assert_eq!(cache["addedLastWeek"], paths);
    }
    assert_eq!(caches[1]["size"], 26);
    assert!(caches[0]["lastAddedAt"].is_null());
    assert!(caches[1]["lastAddedAt"].is_string());
    let (_, _, overview) = call(
        &app,
        "GET",
        "/_api/v1/orgs/org_alpha/overview",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(overview["caches"], listed["caches"]);
    let (_, _, detail) = call(
        &app,
        "GET",
        "/_api/v1/orgs/org_alpha/caches/main",
        Value::Null,
        None,
    )
    .await;
    for (key, value) in caches[1].as_object().unwrap() {
        assert_eq!(&detail[key], value, "{key}");
    }
    let (_, _, all) = call(&app, "GET", "/_api/v1/admin/caches", Value::Null, None).await;
    let beta = all["caches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["org"] == "org_beta")
        .unwrap();
    assert_eq!(beta["servedThisMonth"], 1009);
    assert_eq!(beta["publicServedThisMonth"], 1013);
    assert_eq!(
        beta["servedThisMonthByProduct"],
        json!({"nix":2022,"go":0,"sccache":0})
    );
    let (_, _, empty) = call(
        &app,
        "GET",
        "/_api/v1/admin/caches?org=default",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(empty["caches"], json!([]));
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn metadata_backfill_repairs_recorded_nar_placement(pool: PgPool) {
    let storage = if std::env::var_os("SNOWSTEAD_TEST_R2_ENDPOINT").is_some() {
        Storage::new(&Config::from_env()).unwrap()
    } else {
        common::storage()
    };
    let app = router(state_with_storage(pool.clone(), storage.clone()));
    sqlx::raw_sql("INSERT INTO orgs (id,slug) VALUES ('org_repair','repair');
        INSERT INTO caches (name,org_id,is_public) VALUES ('public','org_repair',true),('secret','org_repair',false);
        INSERT INTO cache_protocols (cache_id,protocol) SELECT id,'nix' FROM caches;")
        .execute(&pool).await.unwrap();
    for private in [false, true] {
        let name = if private { "secret" } else { "public" };
        let hash = if private { "d" } else { "c" }.repeat(64);
        let source = if private {
            format!("nar/{hash}/none.nar")
        } else {
            format!("nars/sha256/{hash}/none.nar")
        };
        let target = if private {
            format!("nars/sha256/{hash}/none.nar")
        } else {
            format!("nar/{hash}/none.nar")
        };
        sqlx::query("INSERT INTO blob_objects (file_hash,file_size,compression,r2_key) VALUES ($1,5,'none',$2)")
            .bind(&hash).bind(&source).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO published_paths (cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id)
            SELECT c.id,repeat('0',32),'/nix/store/00000000000000000000000000000000-example','sha256:'||repeat('0',64),5,b.id
            FROM caches c CROSS JOIN blob_objects b WHERE c.name=$1 AND b.file_hash=$2")
            .bind(name).bind(&hash).execute(&pool).await.unwrap();
        storage.put(!private, &source, b"bytes").await.unwrap();
        assert!(storage.head(private, &target).await.is_err());
    }
    let backfill = || {
        call(
            &app,
            "POST",
            "/_api/v1/admin/narinfo/backfill",
            json!({}),
            None,
        )
    };
    let (status, _, result) = backfill().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        result,
        json!({"written":2,"processed":2,"skipped":[],"next":null})
    );
    for private in [false, true] {
        let (name, hash, prefix) = if private {
            ("secret", "d".repeat(64), "nars/sha256")
        } else {
            ("public", "c".repeat(64), "nar")
        };
        let pointer: String = sqlx::query_scalar(if private {
            "SELECT private_key FROM blob_objects WHERE file_hash=$1"
        } else {
            "SELECT public_key FROM blob_objects WHERE file_hash=$1"
        })
        .bind(&hash)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(pointer.starts_with(if private {
            "nars/objects/"
        } else {
            "nar/objects/"
        }));
        assert!(
            storage
                .head(private, &format!("{prefix}/{hash}/none.nar"))
                .await
                .is_err()
        );
        let object = storage.open(private, &pointer).await.unwrap();
        let mut bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut { object.reader }, &mut bytes)
            .await
            .unwrap();
        assert_eq!(bytes, b"bytes");
        let info_key = format!(
            "{}repair/{name}/{}.narinfo",
            if private { "narinfo/" } else { "" },
            "0".repeat(32)
        );
        assert!(storage.head(private, &info_key).await.is_err());
        assert!(storage.head(!private, &info_key).await.is_err());
        // Once placed, a missing recorded source must not prevent reuse.
        let source = format!(
            "{}/{hash}/none.nar",
            if private { "nar" } else { "nars/sha256" }
        );
        storage.delete(!private, &source).await.unwrap();
    }
    assert_eq!(
        backfill().await.2,
        json!({"written":0,"processed":2,"skipped":[],"next":null})
    );
    let public_key: String =
        sqlx::query_scalar("SELECT public_key FROM blob_objects WHERE file_hash=$1")
            .bind("c".repeat(64))
            .fetch_one(&pool)
            .await
            .unwrap();
    storage.delete(false, &public_key).await.unwrap();
    assert_eq!(
        backfill().await.2,
        json!({"written":0,"processed":1,"skipped":[format!("repair/public/{}", "0".repeat(32))],"next":null})
    );
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn metadata_backfill_slug_move_and_concurrent_slug_claims(pool: PgPool) {
    let one = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    let storage = common::storage();
    let state = state_with_storage(one, storage.clone());
    let app = router(state.clone());
    sqlx::raw_sql("INSERT INTO orgs (id,slug) VALUES ('org_alpha','alpha'); INSERT INTO caches (name,org_id,is_public) VALUES ('public','org_alpha',true),('secret','org_alpha',false);
        INSERT INTO cache_protocols (cache_id,protocol) SELECT id,'nix' FROM caches;
        INSERT INTO blob_objects (file_hash,file_size,compression,r2_key) VALUES (repeat('a',64),5,'none','nar/test');
        INSERT INTO published_paths (cache_id,store_path_hash,store_path,nar_hash,nar_size,blob_object_id) SELECT c.id,repeat('0',32),'/nix/store/00000000000000000000000000000000-example','sha256:'||repeat('0',64),5,b.id FROM caches c CROSS JOIN blob_objects b;").execute(&pool).await.unwrap();
    let blob = format!("nar/{}/none.nar", "a".repeat(64));
    let private = format!("nars/sha256/{}/none.nar", "a".repeat(64));
    storage.put(false, &blob, b"bytes").await.unwrap();
    storage.put(true, &private, b"bytes").await.unwrap();
    let (status, _, written) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        call(
            &app,
            "POST",
            "/_api/v1/admin/narinfo/backfill",
            json!({}),
            None,
        ),
    )
    .await
    .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        written,
        json!({"written":0,"processed":2,"skipped":[],"next":null})
    );
    let hash = "0".repeat(32);
    assert!(
        storage
            .head(false, "alpha/public/nix-cache-info")
            .await
            .is_err()
    );
    assert!(
        storage
            .head(false, "alpha/secret/nix-cache-info")
            .await
            .is_err()
    );
    // Include orphan metadata beyond one page and a default-org cache whose
    // name matches the old slug. Only the old org's two-level keys move.
    for i in 0..205 {
        storage
            .put(false, &format!("alpha/deleted/{i:032}.narinfo"), b"orphan")
            .await
            .unwrap();
    }
    let unrelated = format!("alpha/{hash}.narinfo");
    storage
        .put(false, &unrelated, b"default org")
        .await
        .unwrap();
    storage
        .put(true, "narinfo/alpha/deleted/old.narinfo", b"orphan")
        .await
        .unwrap();
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("/alpha/public/{hash}.narinfo"),
            Value::Null,
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, _, changed) = call(
        &app,
        "PUT",
        "/_api/v1/orgs/org_alpha",
        json!({"slug":"bravo"}),
        None,
    )
    .await;
    assert_eq!(changed["movingFrom"], "alpha");
    assert!(
        storage
            .head(false, "bravo/public/nix-cache-info")
            .await
            .is_err()
    );
    let fresh = format!("narinfo/bravo/secret/{hash}.narinfo");
    storage.put(true, &fresh, b"newer metadata").await.unwrap();
    assert_eq!(
        call(
            &app,
            "PUT",
            "/_api/v1/orgs/org_beta",
            json!({"slug":"alpha"}),
            None
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            "/_api/v1/orgs/org_alpha",
            json!({"slug":"charlie"}),
            None
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (_, _, moved) = call(
        &app,
        "POST",
        "/_api/v1/orgs/org_alpha/move",
        json!({}),
        None,
    )
    .await;
    assert_eq!(moved, json!({"done":true}));
    assert!(storage.head(false, &unrelated).await.is_ok());
    assert!(
        storage
            .head(
                false,
                "alpha/deleted/00000000000000000000000000000000.narinfo"
            )
            .await
            .is_ok()
    );
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM object_cleanup WHERE NOT is_private AND key=$1)"
        )
        .bind(format!("alpha/public/{hash}.narinfo"))
        .fetch_one(&pool)
        .await
        .unwrap()
    );
    assert_eq!(storage.head(true, &fresh).await.unwrap().size, 14);
    assert!(storage.head(false, &blob).await.is_ok());
    assert!(storage.head(true, &private).await.is_ok());
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("/bravo/public/{hash}.narinfo"),
            Value::Null,
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("/alpha/public/{hash}.narinfo"),
            Value::Null,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert!(
        storage
            .open(true, &format!("narinfo/bravo/secret/{hash}.narinfo"))
            .await
            .is_ok()
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            "/_api/v1/orgs/org_beta",
            json!({"slug":"alpha"}),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    let (a, b) = tokio::join!(
        call(
            &app,
            "PUT",
            "/_api/v1/orgs/org_one",
            json!({"slug":"winner"}),
            None
        ),
        call(
            &app,
            "PUT",
            "/_api/v1/orgs/org_two",
            json!({"slug":"winner"}),
            None
        )
    );
    let (a, b) = if a.0 == StatusCode::SERVICE_UNAVAILABLE {
        (
            call(
                &app,
                "PUT",
                "/_api/v1/orgs/org_one",
                json!({"slug":"winner"}),
                None,
            )
            .await,
            b,
        )
    } else if b.0 == StatusCode::SERVICE_UNAVAILABLE {
        (
            a,
            call(
                &app,
                "PUT",
                "/_api/v1/orgs/org_two",
                json!({"slug":"winner"}),
                None,
            )
            .await,
        )
    } else {
        (a, b)
    };
    assert!(matches!(
        (a.0, b.0),
        (StatusCode::OK, StatusCode::CONFLICT) | (StatusCode::CONFLICT, StatusCode::OK)
    ));
    storage.delete(false, &blob).await.unwrap();
    let (_, _, skipped) = call(
        &app,
        "POST",
        "/_api/v1/admin/narinfo/backfill",
        json!({}),
        None,
    )
    .await;
    assert_eq!(skipped["written"], 0);
    assert_eq!(skipped["processed"], 1);
    assert_eq!(skipped["skipped"], json!([format!("bravo/public/{hash}")]));
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn management_limit_is_shared_by_router_clones_and_operator_is_exempt(pool: PgPool) {
    let app = router(state(pool));
    call(
        &app,
        "PUT",
        "/_api/v1/orgs/org_alpha",
        json!({"slug":"alpha"}),
        None,
    )
    .await;
    // Changes made for a person count against that person.
    let revoke = || {
        call(
            &app,
            "POST",
            "/_api/v1/orgs/org_alpha/tokens/missing/revoke",
            json!({"reason":"test"}),
            Some("dev@example.test"),
        )
    };
    for _ in 0..600 {
        assert_ne!(revoke().await.0, StatusCode::TOO_MANY_REQUESTS);
    }
    let (status, headers, value) = revoke().await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(headers["retry-after"], "60");
    assert_eq!(
        value,
        json!({"error":"Too many requests: slow down, and retry in 60 seconds"})
    );
    // Reads the operator makes for that same person are not: a dashboard
    // page view is several, and browsing must not be refused.
    for _ in 0..601 {
        assert_eq!(
            call(
                &app,
                "GET",
                "/_api/v1/orgs/org_alpha",
                Value::Null,
                Some("dev@example.test")
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    assert_eq!(
        call(&app, "GET", "/_api/v1/orgs/org_alpha", Value::Null, None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            "GET",
            "/_api/v1/orgs/org_alpha",
            Value::Null,
            Some("other@example.test")
        )
        .await
        .0,
        StatusCode::OK
    );
}

thread_local! {
    static STATEMENTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Counts the statements sqlx logs on each thread. Every `sqlx::test` owns a
/// current-thread runtime, so a thread's count is one test's count.
struct Statements;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Statements {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() == "sqlx::query" {
            STATEMENTS.set(STATEMENTS.get() + 1);
        }
    }
}

async fn counted(app: &Router, path: &str) -> (usize, Value) {
    use tracing_subscriber::layer::SubscriberExt;
    // Process-wide, not scoped to this thread: tracing caches whether a
    // callsite is enabled, and a parallel test without a subscriber would
    // otherwise cache sqlx's as disabled.
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(Statements))
            .expect("no other global subscriber in tests");
    });
    STATEMENTS.set(0);
    let (status, _, value) = call(app, "GET", path, Value::Null, None).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    (STATEMENTS.get(), value)
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn org_reports_read_the_org_once_and_share_round_trips(pool: PgPool) {
    let app = router(state(pool.clone()));
    let base = "/_api/v1/orgs/org_alpha";
    let (status, _, _) = call(&app, "PUT", base, json!({"slug":"alpha"}), None).await;
    assert_eq!(status, StatusCode::OK);
    sqlx::raw_sql(
        "INSERT INTO caches(name,org_id,size,path_count) VALUES ('main','org_alpha',7,1);
        INSERT INTO cache_protocols(cache_id,protocol) SELECT id,'nix' FROM caches WHERE org_id='org_alpha';
        INSERT INTO upload_sessions(id,cache_id,store_path_hash,store_path,nar_hash,nar_size,file_size,compression,status,expires_at)
        SELECT 'sealed',id,'hash','/nix/store/hash','sha256:test',1,5,'zstd','finalizing',now()-interval '1 day' FROM caches WHERE org_id='org_alpha';
        INSERT INTO bandwidth_daily(org_id,cache_id,product,day,bytes,public_bytes,imported_at)
        SELECT 'org_alpha',id,'nix',(now() AT TIME ZONE 'UTC')::date,11,13,'2026-10-01T00:00:00.123Z' FROM caches WHERE org_id='org_alpha';",
    )
    .execute(&pool)
    .await
    .unwrap();
    let report = json!({"id":"org_alpha","slug":"alpha","movingFrom":null,"storageLimit":null,
        "privateCaches":true,"customSigningKeys":false,"used":7,"pending":5,
        "servedThisMonth":11,"publicServedThisMonth":13,
        "servedThisMonthByProduct":{"nix":24,"go":0,"sccache":0},
        "bandwidthUpdatedAt":"2026-10-01T00:00:00.123Z"});
    // Authorization's org row, then usage (with the import time) and bandwidth.
    let (statements, org) = counted(&app, base).await;
    assert_eq!(org, report);
    assert_eq!(statements, 3);
    // The cache inventory is one more statement, not a second pass.
    let (statements, overview) = counted(&app, &format!("{base}/overview")).await;
    assert_eq!(statements, 4);
    let caches = overview["caches"].as_array().unwrap();
    assert_eq!(caches.len(), 1);
    assert_eq!(caches[0]["name"], "main");
    let mut without = overview.clone();
    without.as_object_mut().unwrap().remove("caches");
    assert_eq!(without, report);
}

#[sqlx::test(migrator = "snowstead_server::migrations::MIGRATOR")]
async fn org_limit_versions_fence_delayed_writes_and_registration(pool: PgPool) {
    let app = router(state(pool.clone()));
    let base = "/_api/v1/orgs/org_fenced";
    let policy = |version: &str, limit: i64| {
        json!({
            "slug":"fenced", "storageLimit":limit, "privateCaches":true,
            "customSigningKeys":true, "limitsVersion":version
        })
    };
    assert_eq!(
        call(&app, "PUT", base, policy("1", 10), None).await.0,
        StatusCode::OK
    );
    let newer = call(&app, "PUT", base, policy("3", 30), None).await;
    assert_eq!(newer.0, StatusCode::OK);
    // A delayed old HTTP request arrives only after the newer one commits.
    let mut stale = policy("2", 20);
    stale["slug"] = json!("stale-registration");
    assert_eq!(call(&app, "PUT", base, stale, None).await.2, newer.2);
    // A duplicate version cannot carry a different policy or rename the org.
    assert_eq!(
        call(&app, "PUT", base, policy("3", 99), None).await.2,
        newer.2
    );
    assert_eq!(
        call(&app, "PUT", base, json!({"storageLimit":99}), None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    for version in [
        json!(null),
        json!(4),
        json!("0"),
        json!("-1"),
        json!("9223372036854775808"),
    ] {
        let mut invalid = policy("4", 40);
        invalid["limitsVersion"] = version;
        assert_eq!(
            call(&app, "PUT", base, invalid, None).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        call(&app, "PUT", base, json!({"limitsVersion":"4"}), None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let newest = call(&app, "PUT", base, policy("9007199254740993", 40), None).await;
    assert_eq!(newest.0, StatusCode::OK);
    assert_eq!(newest.2["storageLimit"], 40);
    // Member slug-only updates remain separate from the operator policy fence.
    assert_eq!(
        call(&app, "PUT", base, json!({"slug":"renamed"}), None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT limits_version FROM orgs WHERE id = 'org_fenced'")
            .fetch_one(&pool)
            .await
            .unwrap(),
        9007199254740993
    );
}
