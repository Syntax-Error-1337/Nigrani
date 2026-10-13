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
            axum::serve(listener, app).await.unwrap();
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
