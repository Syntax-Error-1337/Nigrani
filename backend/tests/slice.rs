//! Slice tests: auth/RBAC (s1) + press KYC workflow (s2).
//!
//! Requires a live Postgres: `docker compose up -d db` then
//! `TEST_DATABASE_URL=postgres://nigrani:nigrani@127.0.0.1:5432/nigrani cargo test`.
//! Rows are UUID-suffixed per test; nothing is shared between tests.

use std::sync::Arc;

use serde_json::{json, Value};

async fn test_state() -> nigrani::api::state::AppState {
    let url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nigrani:nigrani@127.0.0.1:5432/nigrani".into());
    let pool = nigrani::infrastructure::db::connect(&url)
        .await
        .expect("db connect");
    nigrani::infrastructure::db::run_migrations(&pool)
        .await
        .expect("migrations");
    nigrani::infrastructure::seed::seed_users(&pool)
        .await
        .expect("seed");
    nigrani::api::state::AppState {
        pool,
        jwt_secret: Arc::<[u8]>::from(b"test-secret".as_slice()),
        kyc_limiter: nigrani::api::rate_limit::Limiter::kyc(),
        grants: nigrani::api::state::GrantCache::builder()
            .time_to_live(std::time::Duration::from_secs(60))
            .build(),
    }
}

struct TestServer {
    client: reqwest::Client,
    base: String,
}

impl TestServer {
    async fn spawn() -> Self {
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

    async fn login(&self, username: &str) -> String {
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

#[tokio::test]
async fn gate_operator_cannot_create_site() {
    let srv = TestServer::spawn().await;
    let token = srv.login("gate").await;
    let name = format!("nope-{}", uuid::Uuid::new_v4());
    let res = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&token)
        .json(&json!({ "name": name }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let body: Value = res.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("lacks permission"));
}

#[tokio::test]
async fn kyc_approve_press_card_verify_roundtrip() {
    let srv = TestServer::spawn().await;
    // Public submit (no token).
    let full_name = format!("Reporter {}", uuid::Uuid::new_v4());
    let res = srv
        .client
        .post(format!("{}/kyc/applications", srv.base))
        .json(&json!({
            "full_name": full_name,
            "organization": "Test Outlet",
            "document_type": "press_id",
            "document_number": format!("T-{}", uuid::Uuid::new_v4()),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let app: Value = res.json().await.unwrap();
    assert_eq!(app["status"], "pending");
    let id = app["id"].as_str().unwrap().to_owned();

    // Reviewer approves; gate role is denied the queue.
    let verifier = srv.login("verifier").await;
    let gate = srv.login("gate").await;
    let res = srv
        .client
        .get(format!("{}/kyc/applications", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    let res = srv
        .client
        .post(format!("{}/kyc/applications/{id}/decide", srv.base))
        .bearer_auth(&verifier)
        .json(&json!({ "decision": "approved", "note": "ok" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let decided: Value = res.json().await.unwrap();
    assert_eq!(decided["status"], "approved");

    // Re-decide is a conflict.
    let res = srv
        .client
        .post(format!("{}/kyc/applications/{id}/decide", srv.base))
        .bearer_auth(&verifier)
        .json(&json!({ "decision": "rejected" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 409);

    // Press card verifies; tampered copy does not.
    let res = srv
        .client
        .get(format!("{}/kyc/applications/{id}/press-card", srv.base))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let card: Value = res.json().await.unwrap();

    let res = srv
        .client
        .post(format!("{}/kyc/verify", srv.base))
        .bearer_auth(&gate)
        .json(&card)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let verdict: Value = res.json().await.unwrap();
    assert_eq!(verdict["valid"], true);

    let mut bad = card.clone();
    bad["full_name"] = json!("Mallory");
    let res = srv
        .client
        .post(format!("{}/kyc/verify", srv.base))
        .bearer_auth(&gate)
        .json(&bad)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let verdict: Value = res.json().await.unwrap();
    assert_eq!(verdict["valid"], false);
}

#[tokio::test]
async fn kyc_rejects_bad_document_type() {
    let srv = TestServer::spawn().await;
    let res = srv
        .client
        .post(format!("{}/kyc/applications", srv.base))
        .json(&json!({
            "full_name": "X",
            "document_type": "passport",
            "document_number": "1",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn refresh_reuse_burns_session_family() {
    let srv = TestServer::spawn().await;
    // Two independent logins = two live refresh tokens for the same user.
    let first: Value = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": "analyst", "password": "password" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let second: Value = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": "analyst", "password": "password" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let r1 = first["refresh_token"].as_str().unwrap().to_owned();
    let r2 = second["refresh_token"].as_str().unwrap().to_owned();

    // Normal rotation of r1 succeeds…
    let res = srv
        .client
        .post(format!("{}/auth/refresh", srv.base))
        .json(&json!({ "refresh_token": r1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // …then replaying the revoked r1 is flagged as reuse…
    let res = srv
        .client
        .post(format!("{}/auth/refresh", srv.base))
        .json(&json!({ "refresh_token": r1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "refresh token reused");

    // …and the untouched r2 is burned too: the whole family is dead.
    let res = srv
        .client
        .post(format!("{}/auth/refresh", srv.base))
        .json(&json!({ "refresh_token": r2 }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn oversized_login_rejected() {
    let srv = TestServer::spawn().await;
    let res = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": "x".repeat(65), "password": "password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn kyc_submit_rate_limited() {
    let srv = TestServer::spawn().await;
    let mut limited = false;
    for i in 0..12 {
        let res = srv
            .client
            .post(format!("{}/kyc/applications", srv.base))
            .json(&json!({
                "full_name": format!("Flood {i}"),
                "document_type": "pan",
                "document_number": format!("FLOOD-{i}-{}", uuid::Uuid::new_v4()),
            }))
            .send()
            .await
            .unwrap();
        if res.status() == 429 {
            limited = true;
            break;
        }
        assert_eq!(res.status(), 200);
    }
    assert!(limited, "expected 429 within 12 rapid submits");
}

#[tokio::test]
async fn grant_cache_serves_hits_and_invalidation() {
    // Exercises the AppState-constructed cache directly: insert-on-miss,
    // hit without DB, and explicit invalidation on revocation.
    let srv = TestServer::spawn().await;
    let _ = &srv;
    let state = test_state().await;
    let gate_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = 'gate'")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    let user = nigrani::domain::User {
        id: gate_id,
        username: "gate".into(),
        role: nigrani::domain::Role::GateOperator,
    };
    // GateOperator holds gates:read in seed data: first call misses, hits DB.
    nigrani::api::require_permission(&state, &user, "gates:read")
        .await
        .expect("seeded grant");
    assert!(state.grants.get(&("GateOperator".to_owned(), "gates:read".to_owned())).await.is_some());
    // Revoke in DB: cached grant still allows (documented TTL semantics).
    let role_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM roles WHERE name = 'GateOperator'")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    let perm_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM permissions WHERE name = 'gates:read'")
            .fetch_one(&state.pool)
            .await
            .unwrap();
    sqlx::query("DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2")
        .bind(role_id)
        .bind(perm_id)
        .execute(&state.pool)
        .await
        .unwrap();
    nigrani::api::require_permission(&state, &user, "gates:read")
        .await
        .expect("cached grant survives revocation within TTL");
    // Invalidate: denial is now enforced.
    state.grants.invalidate(&("GateOperator".to_owned(), "gates:read".to_owned())).await;
    let err = nigrani::api::require_permission(&state, &user, "gates:read")
        .await
        .expect_err("revoked grant denied after invalidation");
    assert!(err.to_string().contains("lacks permission"));
    // Restore seed for other tests (isolated rows elsewhere, shared role grant).
    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(role_id)
        .bind(perm_id)
        .execute(&state.pool)
        .await
        .unwrap();
}
