//! Shared helpers for the split slice tests.
//! Requires a live Postgres: `docker compose up -d db` then
//! `TEST_DATABASE_URL=postgres://nigrani:nigrani@127.0.0.1:5432/nigrani cargo test`.
//! Rows are UUID-suffixed per test; nothing is shared between tests.

use std::sync::Arc;

pub use serde_json::{json, Value};

/// Retention tests flip one shared policy and purge one shared table;
/// their preview/run steps must not interleave with each other.
// Compiled into every test binary; unused ones would fail -D dead-code.
#[allow(dead_code)]
pub static RETENTION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// Virgin-DB setup races across test binaries, so serialize it with a Postgres
// advisory lock (in-process mutexes don't span test processes).
const SETUP_LOCK: i64 = 8_765_432_109_987;

pub(crate) async fn test_state() -> nigrani::api::state::AppState {
    let url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nigrani:nigrani@127.0.0.1:5432/nigrani".into());
    let pool = nigrani::infrastructure::db::connect(&url)
        .await
        .expect("db connect");
    let mut lock = pool
        .acquire()
        .await
        .expect("acquire advisory-lock connection");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(SETUP_LOCK)
        .fetch_all(&mut *lock)
        .await
        .expect("advisory lock");
    nigrani::infrastructure::db::run_migrations(&pool)
        .await
        .expect("migrations");
    nigrani::infrastructure::seed::seed_users(&pool)
        .await
        .expect("seed");
    sqlx::query("SELECT pg_advisory_unlock($1)") // pool recycles the session, so release explicitly
        .bind(SETUP_LOCK)
        .execute(&mut *lock)
        .await
        .expect("advisory unlock");
    drop(lock);
    nigrani::api::state::AppState {
        pool,
        jwt_secret: Arc::<[u8]>::from(b"test-secret".as_slice()),
        kyc_limiter: nigrani::api::rate_limit::Limiter::kyc(),
        login_limiter: nigrani::api::rate_limit::Limiter::auth_login(),
        refresh_limiter: nigrani::api::rate_limit::Limiter::auth_refresh(),
        snapshot_limiter: nigrani::api::rate_limit::Limiter::snapshot_upload(),
        grants: nigrani::api::state::GrantCache::builder()
            .time_to_live(std::time::Duration::from_secs(60))
            .build(),
        snapshots: None,
        hub: nigrani::api::events::EventHub::new(),
        // Deterministic test key: base64 of 32 0x07 bytes.
        crypto: Some(
            nigrani::infrastructure::crypto::TemplateCrypto::from_base64(
                "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
            )
            .expect("test key"),
        ),
    }
}

pub(crate) struct TestServer {
    pub client: reqwest::Client,
    pub base: String,
}

impl TestServer {
    pub(crate) async fn spawn() -> Self {
        let state = test_state().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = nigrani::api::router(state);
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let client = reqwest::Client::new();
        let base = format!("http://{addr}");
        for _ in 0..50 {
            if let Ok(r) = client.get(format!("{base}/health")).send().await {
                if r.status() == 200 {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Self { client, base }
    }

    pub(crate) async fn login(&self, username: &str) -> String {
        let res = self
            .client
            .post(format!("{}/auth/login", self.base))
            .json(&json!({ "username": username, "password": "password" }))
            .send()
            .await
            .expect("login request");
        assert_eq!(res.status(), 200, "login as {username}");
        res.json::<Value>().await.expect("login json")["access_token"]
            .as_str()
            .expect("access_token")
            .to_owned()
    }
}
