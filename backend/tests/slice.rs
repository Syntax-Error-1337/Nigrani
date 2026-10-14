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
        login_limiter: nigrani::api::rate_limit::Limiter::auth_login(),
        refresh_limiter: nigrani::api::rate_limit::Limiter::auth_refresh(),
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

#[tokio::test]
async fn gate_event_card_and_manual_roundtrip() {
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;
    let gate = srv.login("gate").await;
    let analyst = srv.login("analyst").await;

    // Fixture site + gate (superadmin bypasses write checks).
    let site_name = format!("Kiosk {}", uuid::Uuid::new_v4());
    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": site_name }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();
    let gate_res: Value = srv
        .client
        .post(format!("{}/sites/{site_id}/gates", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": "K1" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gate_id = gate_res["id"].as_str().unwrap().to_owned();

    // Approved application + signed card via reviewer flow.
    let app: Value = srv
        .client
        .post(format!("{}/kyc/applications", srv.base))
        .json(&json!({
            "full_name": format!("Kiosk {}", uuid::Uuid::new_v4()),
            "document_type": "pan",
            "document_number": format!("K-{}", uuid::Uuid::new_v4()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let app_id = app["id"].as_str().unwrap().to_owned();
    let verifier = srv.login("verifier").await;
    srv.client
        .post(format!("{}/kyc/applications/{app_id}/decide", srv.base))
        .bearer_auth(&verifier)
        .json(&json!({ "decision": "approved" }))
        .send()
        .await
        .unwrap();
    let card: Value = srv
        .client
        .get(format!("{}/kyc/applications/{app_id}/press-card", srv.base))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Card entry as gate operator.
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "direction": "entry", "method": "press_card", "press_card": card }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let entry: Value = res.json().await.unwrap();
    assert_eq!(entry["direction"], "entry");
    assert_eq!(entry["application_id"], app_id);

    // Tampered card denied.
    let mut bad = card.clone();
    bad["full_name"] = json!("Mallory");
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "direction": "entry", "method": "press_card", "press_card": bad }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Wrong role denied (analyst lacks entries:write).
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "direction": "entry", "method": "manual" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Cross-site gate rejected.
    let res = srv
        .client
        .post(format!("{}/sites/00000000-0000-0000-0000-000000000000/gates/{gate_id}/events", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "direction": "entry", "method": "manual" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // Manual exit + log shows newest first.
    srv.client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "direction": "exit", "method": "manual" }))
        .send()
        .await
        .unwrap();
    let log: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/gates/{gate_id}/log?limit=5", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(log.as_array().unwrap().len(), 2);
    assert_eq!(log[0]["direction"], "exit");
    assert_eq!(log[1]["method"], "press_card");
}

#[tokio::test]
async fn snapshot_without_storage_is_unavailable() {
    // Test servers carry snapshots: None → clear 503, not a panic.
    let srv = TestServer::spawn().await;
    let gate = srv.login("gate").await;
    let res = srv
        .client
        .post(format!("{}/snapshots", srv.base))
        .bearer_auth(&gate)
        .body(vec![0xFF, 0xD8, 0xFF, 0x00])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 500);
}

fn ones(n: usize) -> Vec<f64> {
    vec![1.0; n]
}

#[tokio::test]
async fn forensics_enroll_search_incidents_heatmap() {
    let srv = TestServer::spawn().await;
    let analyst = srv.login("analyst").await;
    let gate = srv.login("gate").await;
    let superadmin = srv.login("superadmin").await;

    // Near-duplicate enrolls of a distinctive random direction (shared DB
    // may hold residue from other tests, so assert on tight distances).
    // Time-seeded PRNG: every run enrolls unique vectors so residue from
    // prior runs (cosine distance ~1.0 away) falls outside the threshold.
    // (A fixed seed re-enrolled identical vectors and poisoned later runs.)
    let mut seed: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64
        ^ 0x9E3779B97F4A7C15;
    let mut rand = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed as f64) / (u64::MAX as f64) - 0.5
    };
    let base: Vec<f64> = (0..512).map(|_| rand()).collect();
    let mut close = base.clone();
    close[0] += 1e-4;
    // Link enrolls to a fresh application: search hits carry application_id,
    // so residue from other runs (unlinked) cannot pollute assertions.
    let marker: Value = srv
        .client
        .post(format!("{}/kyc/applications", srv.base))
        .json(&json!({
            "full_name": format!("Vector {}", uuid::Uuid::new_v4()),
            "document_type": "pan",
            "document_number": format!("V-{}", uuid::Uuid::new_v4()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let marker_id = marker["id"].as_str().unwrap().to_owned();
    for payload in [base.clone(), close] {
        let res = srv
            .client
            .post(format!("{}/forensics/embeddings", srv.base))
            .bearer_auth(&analyst)
            .json(&json!({ "embedding": payload, "application_id": marker_id }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
    }
    // Wrong dims + gate role denied.
    let res = srv
        .client
        .post(format!("{}/forensics/embeddings", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "embedding": vec![1.0; 10] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let res = srv
        .client
        .post(format!("{}/forensics/search", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "embedding": ones(512) }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Search ranks the near-duplicates first, distant zero-vector excluded
    // by threshold (cosine distance 1.0 from ones-vector).
    let hits: Value = srv
        .client
        .post(format!("{}/forensics/search", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "embedding": base, "threshold": 0.5, "limit": 20 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hits = hits.as_array().unwrap();
    let ours: Vec<&Value> =
        hits.iter().filter(|h| h["application_id"].as_str() == Some(marker_id.as_str())).collect();
    assert_eq!(ours.len(), 2, "both linked enrolls returned");
    assert!(
        ours.iter().all(|h| h["distance"].as_f64().unwrap() < 1e-6),
        "linked near-duplicates rank at ~zero distance"
    );

    // Incident + heatmap on a fresh site.
    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Forensic {}", uuid::Uuid::new_v4()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "title": "Bag", "description": "unattended" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let list: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&analyst)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
    // Gate role cannot file incidents (lacks incidents:write).
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "title": "Nope" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let heat: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/heatmap", srv.base))
        .bearer_auth(&analyst)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(heat.as_array().unwrap().is_empty(), "no gates yet");
}

#[tokio::test]
async fn list_pagination_and_offset_cap() {
    let srv = TestServer::spawn().await;
    let gate = srv.login("gate").await;
    // limit honored
    let one: Value = srv
        .client
        .get(format!("{}/sites?limit=1", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(one.as_array().unwrap().len(), 1);
    // offset pages past the first row
    let all: Value = srv
        .client
        .get(format!("{}/sites?limit=200", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let total = all.as_array().unwrap().len();
    if total > 1 {
        let rest: Value = srv
            .client
            .get(format!("{}/sites?limit=200&offset=1", srv.base))
            .bearer_auth(&gate)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(rest.as_array().unwrap().len(), total - 1);
    }
    // offset cap enforced
    let res = srv
        .client
        .get(format!("{}/sites?offset=10001", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn auth_endpoints_rate_limited() {
    let srv = TestServer::spawn().await;
    let mut limited = false;
    for _ in 0..25 {
        let res = srv
            .client
            .post(format!("{}/auth/login", srv.base))
            .json(&json!({ "username": "nosuch", "password": "x" }))
            .send()
            .await
            .unwrap();
        if res.status() == 429 {
            limited = true;
            break;
        }
    }
    assert!(limited, "expected 429 within 25 rapid logins");
}

#[tokio::test]
async fn logout_revokes_token_and_family() {
    let srv = TestServer::spawn().await;
    // Two sessions for the same user.
    let first: Value = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": "gate", "password": "password" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let second: Value = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": "gate", "password": "password" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let r1 = first["refresh_token"].as_str().unwrap().to_owned();
    let r2 = second["refresh_token"].as_str().unwrap().to_owned();
    let access = second["access_token"].as_str().unwrap().to_owned();

    // Single logout kills only r1.
    let res = srv
        .client
        .post(format!("{}/auth/logout", srv.base))
        .json(&json!({ "refresh_token": r1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = srv
        .client
        .post(format!("{}/auth/refresh", srv.base))
        .json(&json!({ "refresh_token": r1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    // Logout-all kills r2 too.
    let res = srv
        .client
        .post(format!("{}/auth/logout/all", srv.base))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
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
async fn error_responses_carry_request_id() {
    let srv = TestServer::spawn().await;
    let res = srv
        .client
        .get(format!("{}/sites", srv.base))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let header_id = res
        .headers()
        .get("x-request-id")
        .expect("request-id header")
        .to_str()
        .unwrap()
        .to_owned();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["request_id"], header_id);
    assert!(body["error"].is_string());
}

#[tokio::test]
async fn kyc_pii_encrypted_at_rest() {
    let srv = TestServer::spawn().await;
    let doc = format!("ENC-{}", uuid::Uuid::new_v4());
    let app: Value = srv
        .client
        .post(format!("{}/kyc/applications", srv.base))
        .json(&json!({
            "full_name": "Cipher Test",
            "document_type": "aadhaar",
            "document_number": doc,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // API round-trips plaintext …
    assert_eq!(app["document_number"], doc);
    // … while the row holds an opaque envelope.
    let state = test_state().await;
    let stored: String = sqlx::query_scalar("SELECT document_number FROM kyc_applications WHERE id = $1")
        .bind(app["id"].as_str().unwrap().parse::<uuid::Uuid>().unwrap())
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert!(stored.starts_with("v1:"), "ciphertext envelope, got: {stored}");
    assert!(!stored.contains(&doc));
    // A different key cannot read it.
    let wrong =
        nigrani::infrastructure::crypto::TemplateCrypto::from_base64(
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        )
        .unwrap();
    assert!(wrong.decrypt(&stored).is_err());
    // Tampered envelope fails too.
    let right =
        nigrani::infrastructure::crypto::TemplateCrypto::from_base64(
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
        )
        .unwrap();
    assert!(right.decrypt(&format!("{stored}tampered")).is_err());
}

#[tokio::test]
async fn kyc_without_key_fails_closed() {
    // A server booted without BIOMETRIC_KEY refuses PII writes (503-style
    // 500 with a clear message — never silent plaintext).
    let mut state = test_state().await;
    state.crypto = None;
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
    let res = client
        .post(format!("{base}/kyc/applications"))
        .json(&json!({
            "full_name": "No Key",
            "document_type": "pan",
            "document_number": "NK-1",
        }))
        .send()
        .await
        .unwrap();
    // Internal details stay server-side by design; the client sees a loud
    // 500 (not silent plaintext, not a 200).
    assert_eq!(res.status(), 500);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "internal error");
    // And the constructor itself names the missing key.
    std::env::remove_var("BIOMETRIC_KEY");
    match nigrani::infrastructure::crypto::TemplateCrypto::from_env() {
        Ok(_) => panic!("missing key must fail"),
        Err(e) => assert!(e.to_string().contains("BIOMETRIC_KEY")),
    }
}

#[tokio::test]
async fn event_stream_fans_out_crossings() {
    use futures_util::StreamExt;
    let srv = TestServer::spawn().await;
    let gate = srv.login("gate").await;

    // Two subscribers on the same hub.
    let url = format!("{}/events?token={gate}", srv.base.replace("http", "ws"));
    let (mut s1, _) = tokio_tungstenite::connect_async(&url).await.expect("ws1");
    let (mut s2, _) = tokio_tungstenite::connect_async(&url).await.expect("ws2");

    // Trigger a crossing via the API (needs a site + gate fixture).
    let superadmin = srv.login("superadmin").await;
    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Stream {}", uuid::Uuid::new_v4()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();
    let gate_res: Value = srv
        .client
        .post(format!("{}/sites/{site_id}/gates", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": "S1" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gate_id = gate_res["id"].as_str().unwrap().to_owned();
    srv.client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "direction": "entry", "method": "manual" }))
        .send()
        .await
        .unwrap();

    // Both sockets observe the crossing (topology events may arrive first;
    // drain until the crossing appears).
    for sock in [&mut s1, &mut s2] {
        let mut seen_crossing = false;
        for _ in 0..8 {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(5), sock.next())
                .await
                .expect("event in time")
                .expect("ws message")
                .expect("text");
            let text = msg.into_text().expect("text");
            if text.contains("\"kind\":\"crossing\"") && text.contains(&gate_id) {
                seen_crossing = true;
                break;
            }
        }
        assert!(seen_crossing, "crossing event fanned out");
    }

    // Bad token rejected (WS handshake fails).
    let bad = format!("{}/events?token=nope", srv.base.replace("http", "ws"));
    assert!(tokio_tungstenite::connect_async(&bad).await.is_err());
}

#[tokio::test]
async fn audit_trail_records_and_verifies() {
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;
    let gate = srv.login("gate").await;

    // A failed login is recorded (actor unknown).
    srv.client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": "ghost", "password": "x" }))
        .send()
        .await
        .unwrap();
    // A gate denial for the viewer role.
    let res = srv
        .client
        .get(format!("{}/audit", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Trail shows the failed login; chain verifies.
    let trail: Value = srv
        .client
        .get(format!("{}/audit?entity=session&limit=5", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(trail.as_array().unwrap().iter().any(|e| e["action"] == "login.failed"));
    let verdict: Value = srv
        .client
        .get(format!("{}/audit/verify", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verdict["ok"], true);
    assert!(verdict["checked"].as_i64().unwrap() >= 1);

    // Tamper with a row's detail directly → verifier names it.
    // Originals are captured and restored: the shared dev DB must keep a
    // valid chain after this test (see the seq-3 repair saga).
    let state = test_state().await;
    let victim: (i64, Value, String) =
        sqlx::query_as("SELECT seq, detail, hash FROM audit_log ORDER BY seq DESC LIMIT 1")
            .fetch_one(&state.pool)
            .await
            .unwrap();
    sqlx::query("UPDATE audit_log SET detail = '{\"forged\": true}' WHERE seq = $1")
        .bind(victim.0)
        .execute(&state.pool)
        .await
        .unwrap();
    let verdict: Value = srv
        .client
        .get(format!("{}/audit/verify", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verdict["ok"], false);
    assert_eq!(verdict["first_bad"], victim.0);
    // Restore: original detail + hash byte-for-byte (successor linkage intact
    // because only this row's pair changes back to its committed values).
    sqlx::query("UPDATE audit_log SET detail = $1, hash = $2 WHERE seq = $3")
        .bind(victim.1)
        .bind(victim.2)
        .bind(victim.0)
        .execute(&state.pool)
        .await
        .unwrap();
    let verdict: Value = srv
        .client
        .get(format!("{}/audit/verify", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verdict["ok"], true);
}

#[tokio::test]
async fn retention_purge_and_export() {
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;
    let gate = srv.login("gate").await;

    // Admin endpoints gated.
    let res = srv
        .client
        .get(format!("{}/admin/retention/policies", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Tune embeddings window to 1 day, then plant an old + a fresh row.
    let res = srv
        .client
        .post(format!("{}/admin/retention/policies/face_embeddings", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "retain_days": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let state = test_state().await;
    let old_vec = format!("[{}]", vec!["0.5"; 512].join(","));
    sqlx::query(
        "INSERT INTO face_embeddings (embedding, captured_at) VALUES ($1::vector, now() - interval '5 days')",
    )
    .bind(&old_vec)
    .execute(&state.pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO face_embeddings (embedding) VALUES ($1::vector)")
        .bind(&old_vec)
        .execute(&state.pool)
        .await
        .unwrap();

    // Purge removes only the expired row and reports counts.
    let report: Value = srv
        .client
        .post(format!("{}/admin/retention/run", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(report["purged"]["face_embeddings"], 1);
    let remaining: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM face_embeddings WHERE captured_at < now() - interval '1 day'")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(remaining.0, 0);

    // Restore the default window so other runs are unaffected.
    srv.client
        .post(format!("{}/admin/retention/policies/face_embeddings", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "retain_days": 180 }))
        .send()
        .await
        .unwrap();

    // Export shape on a fresh site.
    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Export {}", uuid::Uuid::new_v4()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();
    let export: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/export", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(export["site_id"], site_id);
    assert!(export["gates"].is_array() && export["entry_logs"].is_array() && export["incidents"].is_array());
}

#[tokio::test]
async fn press_card_png_decodes_to_signed_payload() {
    let srv = TestServer::spawn().await;
    let verifier = srv.login("verifier").await;
    let gate = srv.login("gate").await;

    // Approved application fixture.
    let app: Value = srv
        .client
        .post(format!("{}/kyc/applications", srv.base))
        .json(&json!({
            "full_name": format!("QR {}", uuid::Uuid::new_v4()),
            "document_type": "press_id",
            "document_number": format!("Q-{}", uuid::Uuid::new_v4()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let app_id = app["id"].as_str().unwrap().to_owned();
    srv.client
        .post(format!("{}/kyc/applications/{app_id}/decide", srv.base))
        .bearer_auth(&verifier)
        .json(&json!({ "decision": "approved" }))
        .send()
        .await
        .unwrap();

    // JSON + PNG endpoints agree; PNG is a real PNG.
    let card: Value = srv
        .client
        .get(format!("{}/kyc/applications/{app_id}/press-card", srv.base))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let res = srv
        .client
        .get(format!("{}/kyc/applications/{app_id}/press-card.png", srv.base))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers().get("content-type").unwrap(), "image/png");
    let bytes = res.bytes().await.unwrap();
    assert!(bytes.starts_with(b"\x89PNG"), "PNG magic");
    assert!(bytes.len() > 1_000, "non-trivial image");

    // Independent decode (rxing) recovers the exact signed payload.
    use rxing::Reader;
    let img = image::load_from_memory(&bytes).unwrap().to_luma8();
    let (w, h) = (img.width(), img.height());
    let source = rxing::Luma8LuminanceSource::new(img.into_raw(), w, h).expect("luma source");
    let mut bitmap =
        rxing::BinaryBitmap::new(rxing::common::HybridBinarizer::new(source));
    let decoded = rxing::qrcode::QRCodeReader::new()
        .decode(&mut bitmap)
        .expect("qr decodes");
    let scanned: Value = serde_json::from_str(decoded.getText()).expect("payload JSON");
    // Same card, independently issued: identity fields agree; timestamps
    // differ because each endpoint signs at request time.
    for field in ["application_id", "full_name", "organization"] {
        assert_eq!(scanned[field], card[field], "field {field} agrees");
    }

    // The scanned payload verifies at the gate.
    for payload in [&scanned, &card] {
        let verdict: Value = srv
            .client
            .post(format!("{}/kyc/verify", srv.base))
            .bearer_auth(&gate)
            .json(payload)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(verdict["valid"], true);
    }
}

#[tokio::test]
async fn foreign_key_rows_redact_not_fail() {
    // A row encrypted under a different key degrades to placeholders;
    // the list stays 200 so one bad row never blinds the desk.
    let srv = TestServer::spawn().await;
    let verifier = srv.login("verifier").await;
    let doc = format!("FOREIGN-{}", uuid::Uuid::new_v4());
    srv.client
        .post(format!("{}/kyc/applications", srv.base))
        .json(&json!({
            "full_name": "Foreign Key",
            "document_type": "pan",
            "document_number": doc,
        }))
        .send()
        .await
        .unwrap();
    // Rewrite that row's envelope under a foreign key directly in SQL.
    let state = test_state().await;
    let foreign =
        nigrani::infrastructure::crypto::TemplateCrypto::from_base64(
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        )
        .unwrap();
    let row_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM kyc_applications WHERE document_number LIKE 'v1:%' AND full_name = 'Foreign Key' ORDER BY submitted_at DESC LIMIT 1")
            .fetch_one(&state.pool)
            .await
            .unwrap();
    // Re-encrypt the KNOWN plaintext under the foreign key (simulates a
    // row written by another deployment sharing the table).
    let foreign_envelope = foreign.encrypt(&doc).unwrap();
    sqlx::query("UPDATE kyc_applications SET document_number = $1 WHERE id = $2")
        .bind(&foreign_envelope)
        .bind(row_id)
        .execute(&state.pool)
        .await
        .unwrap();
    // The pending queue holds flood residue; page until the row appears.
    let mut hit = None;
    for offset in [0, 200, 400, 600] {
        let list: Value = srv
            .client
            .get(format!(
                "{}/kyc/applications?status=pending&limit=200&offset={offset}",
                srv.base
            ))
            .bearer_auth(&verifier)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let page = list.as_array().unwrap().clone();
        if page.is_empty() {
            break;
        }
        if let Some(e) = page.iter().find(|e| e["id"] == row_id.to_string()) {
            hit = Some(e.clone());
            break;
        }
    }
    let hit = hit.expect("foreign row still listed");
    assert!(
        hit["document_number"].as_str().unwrap().contains("undecryptable"),
        "redacted placeholder, got: {}",
        hit["document_number"]
    );
}

#[tokio::test]
async fn demo_search_narrows_lists() {
    let srv = TestServer::spawn().await;
    let gate = srv.login("gate").await;
    let all: Value = srv
        .client
        .get(format!("{}/sites?limit=200", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!all.as_array().unwrap().is_empty());
    let jantar: Value = srv
        .client
        .get(format!("{}/sites?q=jantar", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = jantar
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert!(!names.is_empty());
    assert!(names.iter().all(|n| n.to_lowercase().contains("jantar")));
    // Gate role cannot reset; tested against superadmin below in full run.
    let res = srv
        .client
        .post(format!("{}/admin/demo/reset", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
}

// Destructive: truncates all operational tables. Opt-in via env so the
// parallel suite never observes a wiped database; run explicitly:
//   RUN_DESTRUCTIVE_TESTS=1 cargo test demo_reset -- --test-threads=1 --nocapture
#[tokio::test]
async fn demo_reset_restores_baseline() {
    if std::env::var("RUN_DESTRUCTIVE_TESTS").as_deref() != Ok("1") {
        return;
    }
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;
    let report: Value = srv
        .client
        .post(format!("{}/admin/demo/reset", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(report["truncated"].is_object());
    // Baseline: exactly Jantar Mantar + 4 gates + 5 users + 5 policies.
    let state = test_state().await;
    let sites: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sites").fetch_one(&state.pool).await.unwrap();
    let gates: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM gates").fetch_one(&state.pool).await.unwrap();
    let users: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users").fetch_one(&state.pool).await.unwrap();
    let policies: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM retention_policies").fetch_one(&state.pool).await.unwrap();
    assert_eq!((sites.0, gates.0, users.0, policies.0), (1, 4, 5, 5));
    // Genesis audit row opens the new trail.
    let genesis: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE action = 'demo.reset'")
            .fetch_one(&state.pool)
            .await
            .unwrap();
    assert_eq!(genesis.0, 1);
}

#[tokio::test]
async fn provisioning_lifecycle() {
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;
    let gate = srv.login("gate").await;

    // Gate role cannot provision.
    let res = srv
        .client
        .post(format!("{}/users", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "username": "nope", "password": "long-enough-pw", "role": "GateOperator" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    // Weak password rejected.
    let res = srv
        .client
        .post(format!("{}/users", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "username": "weak", "password": "short", "role": "GateOperator" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);

    // Provision → login works.
    let name = format!("op_{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let created: Value = srv
        .client
        .post(format!("{}/users", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "username": name, "password": "fresh-operator-pw", "role": "GateOperator" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let uid = created["id"].as_str().unwrap().to_owned();
    let session: Value = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": name, "password": "fresh-operator-pw" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let refresh = session["refresh_token"].as_str().unwrap().to_owned();

    // Deactivate → login + refresh die; reactivate → login works.
    srv.client
        .post(format!("{}/users/{uid}/deactivate", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap();
    for payload in [
        json!({ "username": name, "password": "fresh-operator-pw" }),
    ] {
        let res = srv
            .client
            .post(format!("{}/auth/login", srv.base))
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 401);
    }
    let res = srv
        .client
        .post(format!("{}/auth/refresh", srv.base))
        .json(&json!({ "refresh_token": refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    srv.client
        .post(format!("{}/users/{uid}/reactivate", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap();
    let res = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": name, "password": "fresh-operator-pw" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Password change: wrong current 401s; correct rotates + kills old refresh.
    let me: Value = res.json().await.unwrap();
    let my_token = me["access_token"].as_str().unwrap().to_owned();
    let my_refresh = me["refresh_token"].as_str().unwrap().to_owned();
    let res = srv
        .client
        .post(format!("{}/auth/password", srv.base))
        .bearer_auth(&my_token)
        .json(&json!({ "current": "wrong-pw", "new": "rotated-operator-pw" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let res = srv
        .client
        .post(format!("{}/auth/password", srv.base))
        .bearer_auth(&my_token)
        .json(&json!({ "current": "fresh-operator-pw", "new": "rotated-operator-pw" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = srv
        .client
        .post(format!("{}/auth/refresh", srv.base))
        .json(&json!({ "refresh_token": my_refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let res = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": name, "password": "rotated-operator-pw" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn incident_lifecycle_transitions_assign_links() {
    let srv = TestServer::spawn().await;
    let analyst = srv.login("analyst").await;
    let gate = srv.login("gate").await;
    let superadmin = srv.login("superadmin").await;

    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Cases {}", uuid::Uuid::new_v4()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();

    let inc: Value = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "title": "Door forced" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(inc["status"], "open");
    let iid = inc["id"].as_str().unwrap().to_owned();

    // Illegal jump open -> resolved is a 409, not a silent skip.
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents/{iid}/status", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "status": "resolved" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 409);

    // Full chain open -> investigating -> resolved -> closed.
    for want in ["investigating", "resolved", "closed"] {
        let got: Value = srv
            .client
            .post(format!("{}/sites/{site_id}/incidents/{iid}/status", srv.base))
            .bearer_auth(&analyst)
            .json(&json!({ "status": want }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(got["status"], want);
    }
    // Resolved stamps, close keeps the stamp.
    let reopened: Value = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents/{iid}/status", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "status": "investigating" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reopened["status"], "investigating");

    // Assign to someone who holds incidents:write (analyst's own id via /users).
    let users: Value = srv
        .client
        .get(format!("{}/users", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let analyst_id = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "analyst")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let gate_id = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "gate")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let assigned: Value = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents/{iid}/assign", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "user_id": analyst_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(assigned["assigned_to"], analyst_id);
    // Gate staff lack incidents:write: refused, not silently assigned.
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents/{iid}/assign", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "user_id": gate_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);

    // Gate role cannot transition either.
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents/{iid}/status", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "status": "investigating" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Evidence link round-trip: note + bad-kind rejection.
    let link: Value = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents/{iid}/links", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "kind": "note", "note": "witness statement taken" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(link["kind"], "note");
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents/{iid}/links", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "kind": "cctv" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let links: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/incidents/{iid}/links", srv.base))
        .bearer_auth(&analyst)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(links.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn incident_events_fan_out_and_coverage() {
    use futures_util::StreamExt;
    let srv = TestServer::spawn().await;
    let analyst = srv.login("analyst").await;
    let superadmin = srv.login("superadmin").await;
    let url = format!("{}/events?token={analyst}", srv.base.replace("http", "ws"));
    let (mut sock, _) = tokio_tungstenite::connect_async(&url).await.expect("ws");

    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("CaseStream {}", uuid::Uuid::new_v4()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();
    let inc: Value = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "title": "Wire case" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let iid = inc["id"].as_str().unwrap().to_owned();
    srv.client
        .post(format!("{}/sites/{site_id}/incidents/{iid}/status", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "status": "investigating" }))
        .send()
        .await
        .unwrap();
    let users: Value = srv
        .client
        .get(format!("{}/users", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let analyst_id = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "analyst")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    srv.client
        .post(format!("{}/sites/{site_id}/incidents/{iid}/assign", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "user_id": analyst_id }))
        .send()
        .await
        .unwrap();
    srv.client
        .post(format!("{}/sites/{site_id}/incidents/{iid}/links", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "kind": "note", "note": "wire note" }))
        .send()
        .await
        .unwrap();

    // Drain until all four incident actions arrive (topology noise first).
    let mut seen = std::collections::HashSet::new();
    for _ in 0..16 {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), sock.next())
            .await
            .expect("event in time")
            .expect("ws message")
            .expect("text");
        let text = msg.into_text().expect("text");
        if text.contains("\"kind\":\"incident\"") && text.contains(&iid) {
            for action in ["created", "status", "assigned", "linked"] {
                if text.contains(&format!("\"action\":\"{action}\"")) {
                    seen.insert(action);
                }
            }
        }
        if seen.len() == 4 {
            break;
        }
    }
    assert_eq!(seen.len(), 4, "all four incident actions fanned out: {seen:?}");

    // Export carries the lifecycle fields + links array.
    let export: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/export", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = export["incidents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == iid)
        .expect("case in export");
    assert_eq!(row["status"], "investigating");
    assert_eq!(row["assigned_to"], analyst_id);
    assert!(export["incident_links"].is_array());
    assert_eq!(export["incident_links"].as_array().unwrap().len(), 1);

    // Backdate the case + link to 5 days, tighten windows to 1 day, purge both.
    let state = test_state().await;
    sqlx::query("UPDATE incidents SET created_at = now() - interval '5 days' WHERE id = $1::uuid")
        .bind(&iid)
        .execute(&state.pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE incident_links SET added_at = now() - interval '5 days' WHERE incident_id = $1::uuid",
    )
    .bind(&iid)
    .execute(&state.pool)
    .await
    .unwrap();
    for entity in ["incidents", "incident_links"] {
        srv.client
            .post(format!("{}/admin/retention/policies/{entity}", srv.base))
            .bearer_auth(&superadmin)
            .json(&json!({ "retain_days": 1 }))
            .send()
            .await
            .unwrap();
    }
    let report: Value = srv
        .client
        .post(format!("{}/admin/retention/run", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(report["purged"]["incident_links"], 1);
    assert_eq!(report["purged"]["incidents"], 1);
    for entity in ["incidents", "incident_links"] {
        srv.client
            .post(format!("{}/admin/retention/policies/{entity}", srv.base))
            .bearer_auth(&superadmin)
            .json(&json!({ "retain_days": 365 }))
            .send()
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn kyc_duplicate_document_blocked_then_reapplies() {
    let srv = TestServer::spawn().await;
    let verifier = srv.login("verifier").await;
    let doc = format!("DUP-{}", uuid::Uuid::new_v4());

    // First submit: 200, no priors.
    let first: Value = srv
        .client
        .post(format!("{}/kyc/applications", srv.base))
        .json(&json!({
            "full_name": "Repeat Reporter",
            "document_type": "pan",
            "document_number": doc,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first["status"], "pending");
    assert_eq!(first["prior_decisions"], 0);
    let first_id = first["id"].as_str().unwrap().to_owned();

    // Same document, different case + padding: 409 (normalization works).
    let res = srv
        .client
        .post(format!("{}/kyc/applications", srv.base))
        .json(&json!({
            "full_name": "Repeat Reporter",
            "document_type": "pan",
            "document_number": format!("  {}  ", doc.to_lowercase()),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 409);

    // Different document type, same number: NOT a duplicate (namespaced).
    let other: Value = srv
        .client
        .post(format!("{}/kyc/applications", srv.base))
        .json(&json!({
            "full_name": "Repeat Reporter",
            "document_type": "aadhaar",
            "document_number": doc,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(other["status"], "pending");

    // Reject the first; resubmit now succeeds with prior_decisions = 1.
    let res = srv
        .client
        .post(format!("{}/kyc/applications/{first_id}/decide", srv.base))
        .bearer_auth(&verifier)
        .json(&json!({ "decision": "rejected", "note": "blurry scan" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let retry: Value = srv
        .client
        .post(format!("{}/kyc/applications", srv.base))
        .json(&json!({
            "full_name": "Repeat Reporter",
            "document_type": "pan",
            "document_number": doc,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(retry["status"], "pending");
    assert_eq!(retry["prior_decisions"], 1);

    // Reviewer queue surfaces the repeat signal on the decided row too.
    let rejected: Value = srv
        .client
        .get(format!("{}/kyc/applications?status=rejected", srv.base))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = rejected
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == first_id)
        .expect("decided row in queue");
    assert_eq!(row["prior_decisions"], 0, "no OTHER decided rows share it yet");
}

#[tokio::test]
async fn login_lockout_triggers_and_unlocks() {
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;

    // Fresh victim via provisioning (SuperAdmin-only create).
    let name = format!("lockme_{}", uuid::Uuid::new_v4().to_string().replace('-', "")[..12].to_owned());
    let created: Value = srv
        .client
        .post(format!("{}/users", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "username": name, "password": "victim-password-1", "role": "GateOperator" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let uid = created["id"].as_str().unwrap().to_owned();
    let bad = |pw: &str| {
        let client = &srv.client;
        let base = srv.base.clone();
        let name = name.clone();
        let pw = pw.to_owned();
        async move {
            client
                .post(format!("{base}/auth/login"))
                .json(&json!({ "username": name, "password": pw }))
                .send()
                .await
                .unwrap()
                .status()
        }
    };

    // Four strikes: still plain 401s, counter climbs, no lock.
    for _ in 0..4 {
        assert_eq!(bad("wrong-password-1").await, 401);
    }
    // A success here resets the counter (proves the reset path).
    let res = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": name, "password": "victim-password-1" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let me: Value = res.json().await.unwrap();
    assert!(me["user"]["locked_until"].is_null());

    // Five consecutive failures → locked. Correct password now also 401.
    for _ in 0..5 {
        assert_eq!(bad("wrong-password-1").await, 401);
    }
    assert_eq!(bad("victim-password-1").await, 401, "locked: right password rejected");

    // Non-SuperAdmin unlock refused; self-unlock refused.
    let gate = srv.login("gate").await;
    let res = srv
        .client
        .post(format!("{}/users/{uid}/unlock", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let res = srv
        .client
        .post(format!("{}/users/{uid}/unlock", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Login works again after unlock.
    let res = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": name, "password": "victim-password-1" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn topology_retirement_archive_restore_guards() {
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;
    let gate = srv.login("gate").await;

    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Retire {}", uuid::Uuid::new_v4()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();
    let g: Value = srv
        .client
        .post(format!("{}/sites/{site_id}/gates", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": "G1" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gate_id = g["id"].as_str().unwrap().to_owned();

    // Site with a live gate refuses to archive.
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/archive/archive", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 409);

    // Archive the gate: crossings go 410, lists hide it.
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/archive/archive", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "direction": "entry", "method": "manual" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 410);
    let gates: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/gates", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(gates.as_array().unwrap().is_empty());
    let gates: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/gates?include=archived", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(gates.as_array().unwrap().len(), 1);

    // Now the site archives; incidents + gates-create go 410 there.
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/archive/archive", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let analyst = srv.login("analyst").await;
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "title": "Nope" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 410);
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": "G2" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 410);

    // Gate role cannot archive (needs gates:write).
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/archive/restore", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Restore both: crossings flow again.
    for (url, want) in [
        (format!("{}/sites/{site_id}/gates/{gate_id}/archive/restore", srv.base), 200),
        (format!("{}/sites/{site_id}/archive/restore", srv.base), 200),
    ] {
        let res = srv.client.post(url).bearer_auth(&superadmin).send().await.unwrap();
        assert_eq!(res.status(), want);
    }
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "direction": "entry", "method": "manual" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn press_card_revocation_kills_scans() {
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;
    let gate = srv.login("gate").await;
    let verifier = srv.login("verifier").await;

    // Fixture site + gate + approved application + card.
    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Revoke {}", uuid::Uuid::new_v4()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();
    let g: Value = srv
        .client
        .post(format!("{}/sites/{site_id}/gates", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": "R1" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gate_id = g["id"].as_str().unwrap().to_owned();
    let app: Value = srv
        .client
        .post(format!("{}/kyc/applications", srv.base))
        .json(&json!({
            "full_name": format!("Revoke {}", uuid::Uuid::new_v4()),
            "document_type": "pan",
            "document_number": format!("R-{}", uuid::Uuid::new_v4()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let app_id = app["id"].as_str().unwrap().to_owned();
    srv.client
        .post(format!("{}/kyc/applications/{app_id}/decide", srv.base))
        .bearer_auth(&verifier)
        .json(&json!({ "decision": "approved" }))
        .send()
        .await
        .unwrap();
    let card: Value = srv
        .client
        .get(format!("{}/kyc/applications/{app_id}/press-card", srv.base))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Healthy card: verify ok + gate scan 200.
    let verdict: Value = srv
        .client
        .post(format!("{}/kyc/verify", srv.base))
        .bearer_auth(&gate)
        .json(&card)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verdict["valid"], true);
    assert_eq!(verdict["reason"], "ok");
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "direction": "entry", "method": "press_card", "press_card": card }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Revoke pending application → 409 (only approved rows carry cards).
    let other: Value = srv
        .client
        .post(format!("{}/kyc/applications", srv.base))
        .json(&json!({
            "full_name": "Pending Pete",
            "document_type": "pan",
            "document_number": format!("P-{}", uuid::Uuid::new_v4()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let res = srv
        .client
        .post(format!("{}/kyc/applications/{}/revoke-card", srv.base, other["id"].as_str().unwrap()))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 409);
    // Gate role cannot revoke (needs kyc:review).
    let res = srv
        .client
        .post(format!("{}/kyc/applications/{app_id}/revoke-card", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Revoke: verify says revoked, gate scan 403s, manual still flows.
    let revoked: Value = srv
        .client
        .post(format!("{}/kyc/applications/{app_id}/revoke-card", srv.base))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(revoked["card_revoked_at"].is_string());
    let verdict: Value = srv
        .client
        .post(format!("{}/kyc/verify", srv.base))
        .bearer_auth(&gate)
        .json(&card)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verdict["valid"], false);
    assert_eq!(verdict["reason"], "revoked");
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "direction": "entry", "method": "press_card", "press_card": card }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "direction": "entry", "method": "manual" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    // Idempotent second revoke.
    let res = srv
        .client
        .post(format!("{}/kyc/applications/{app_id}/revoke-card", srv.base))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn snapshot_collect_without_storage_is_unavailable() {
    // Test servers carry snapshots: None → collect fails the same closed
    // way as upload (500, not a panic). Real collection is proven live
    // against LocalStack (orphan dry-run + delete + attached survival).
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;
    let gate = srv.login("gate").await;
    let res = srv
        .client
        .post(format!("{}/admin/snapshots/collect", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "dry_run": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 500);
    // Non-SuperAdmin refused before the storage check.
    let res = srv
        .client
        .post(format!("{}/admin/snapshots/collect", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "dry_run": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
}

#[tokio::test]
async fn forensic_references_validate_before_write() {
    let srv = TestServer::spawn().await;
    let analyst = srv.login("analyst").await;
    let superadmin = srv.login("superadmin").await;
    let ghost = uuid::Uuid::new_v4().to_string();

    // Enroll with dangling references → 404s, not 500s.
    let ones: Vec<f32> = vec![1.0; 512];
    for (field, status) in [("entry_log_id", 404), ("application_id", 404)] {
        let res = srv
            .client
            .post(format!("{}/forensics/embeddings", srv.base))
            .bearer_auth(&analyst)
            .json(&serde_json::json!({ "embedding": ones, field: ghost }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), status, "{field} dangling");
    }

    // Incident with dangling suspect → 404.
    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Refcheck {}", uuid::Uuid::new_v4()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "title": "Ghost suspect", "suspect_application_id": ghost }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // Valid incident + cross-site entry link → 400; bogus embedding → 404.
    let inc: Value = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "title": "Refcase" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let iid = inc["id"].as_str().unwrap().to_owned();
    let other: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Otherside {}", uuid::Uuid::new_v4()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let other_id = other["id"].as_str().unwrap().to_owned();
    let g: Value = srv
        .client
        .post(format!("{}/sites/{other_id}/gates", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": "X1" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gate = srv.login("gate").await;
    let ev: Value = srv
        .client
        .post(format!("{}/sites/{other_id}/gates/{}/events", srv.base, g["id"].as_str().unwrap()))
        .bearer_auth(&gate)
        .json(&json!({ "direction": "entry", "method": "manual" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    for (kind, ref_id, want) in [
        ("entry", ev["id"].as_str().unwrap().to_owned(), 400),
        ("entry", ghost.clone(), 404),
        ("embedding", ghost.clone(), 404),
    ] {
        let res = srv
            .client
            .post(format!("{}/sites/{site_id}/incidents/{iid}/links", srv.base))
            .bearer_auth(&analyst)
            .json(&json!({ "kind": kind, "ref_id": ref_id, "note": "x" }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), want, "{kind}/{ref_id}");
    }
}

#[tokio::test]
async fn incident_list_filters_by_status_and_assignee() {
    let srv = TestServer::spawn().await;
    let analyst = srv.login("analyst").await;
    let superadmin = srv.login("superadmin").await;
    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Triage {}", uuid::Uuid::new_v4()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();
    // Two cases: one stays open, one advances to investigating + assignee.
    let mk = |title: &str| {
        let client = &srv.client;
        let base = srv.base.clone();
        let site_id = site_id.clone();
        let analyst = analyst.clone();
        let title = title.to_owned();
        async move {
            client
                .post(format!("{base}/sites/{site_id}/incidents"))
                .bearer_auth(&analyst)
                .json(&json!({ "title": title }))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let a = mk("Triage Alpha").await;
    let b = mk("Triage Beta").await;
    let users: Value = srv
        .client
        .get(format!("{}/users", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let analyst_id = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "analyst")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let iid_b = b["id"].as_str().unwrap().to_owned();
    srv.client
        .post(format!("{}/sites/{site_id}/incidents/{iid_b}/status", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "status": "investigating" }))
        .send()
        .await
        .unwrap();
    srv.client
        .post(format!("{}/sites/{site_id}/incidents/{iid_b}/assign", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "user_id": analyst_id }))
        .send()
        .await
        .unwrap();

    let get = |q: &str| {
        let client = &srv.client;
        let base = srv.base.clone();
        let site_id = site_id.clone();
        let analyst = analyst.clone();
        let q = q.to_owned();
        async move {
            client
                .get(format!("{base}/sites/{site_id}/incidents{q}"))
                .bearer_auth(&analyst)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let open = get("?status=open").await;
    assert!(open.as_array().unwrap().iter().any(|r| r["id"] == a["id"]));
    assert!(open.as_array().unwrap().iter().all(|r| r["id"] != b["id"]));
    let inv = get("?status=investigating").await;
    assert!(inv.as_array().unwrap().iter().any(|r| r["id"] == b["id"]));
    let mine = get("?assignee=me").await;
    assert!(mine.as_array().unwrap().iter().any(|r| r["id"] == b["id"]));
    assert!(mine.as_array().unwrap().iter().all(|r| r["id"] != a["id"]));
    let both = get("?status=investigating&assignee=me").await;
    assert_eq!(both.as_array().unwrap().len(), 1);
    // Garbage status + garbage assignee rejected, not ignored.
    let res = srv
        .client
        .get(format!("{}/sites/{site_id}/incidents?status=bogus", srv.base))
        .bearer_auth(&analyst)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let res = srv
        .client
        .get(format!("{}/sites/{site_id}/incidents?assignee=nope", srv.base))
        .bearer_auth(&analyst)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn event_snapshot_key_hygiene() {
    // No-storage test server: format enforced, existence skipped.
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;
    let gate = srv.login("gate").await;
    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Hygiene {}", uuid::Uuid::new_v4()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();
    let g: Value = srv
        .client
        .post(format!("{}/sites/{site_id}/gates", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": "H1" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gate_id = g["id"].as_str().unwrap().to_owned();
    let post = |key: Option<&str>| {
        let client = &srv.client;
        let base = srv.base.clone();
        let site_id = site_id.clone();
        let gate_id = gate_id.clone();
        let gate = gate.clone();
        let key = key.map(str::to_owned);
        async move {
            client
                .post(format!("{base}/sites/{site_id}/gates/{gate_id}/events"))
                .bearer_auth(&gate)
                .json(&json!({ "direction": "entry", "method": "manual", "snapshot_key": key }))
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    // Traversal / wrong suffix / non-UUID stem rejected even without S3.
    assert_eq!(post(Some("../../etc/passwd")).await, 400);
    assert_eq!(post(Some("photo.png")).await, 400);
    assert_eq!(post(Some("not-a-uuid.jpg")).await, 400);
    // Well-formed-but-absent passes without storage (existence skipped);
    // empty (no photo) always passes.
    assert_eq!(post(Some(&format!("{}.jpg", uuid::Uuid::new_v4()))).await, 200);
    assert_eq!(post(None).await, 200);
}

#[tokio::test]
async fn site_audit_includes_incident_trail() {
    let srv = TestServer::spawn().await;
    let analyst = srv.login("analyst").await;
    let superadmin = srv.login("superadmin").await;
    let mk_site = |name: String| {
        let client = &srv.client;
        let base = srv.base.clone();
        let superadmin = superadmin.clone();
        async move {
            client
                .post(format!("{base}/sites"))
                .bearer_auth(&superadmin)
                .json(&json!({ "name": name }))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let a = mk_site(format!("CaseAudit {}", uuid::Uuid::new_v4())).await;
    let b = mk_site(format!("Elsewhere {}", uuid::Uuid::new_v4())).await;
    let aid = a["id"].as_str().unwrap().to_owned();
    let bid = b["id"].as_str().unwrap().to_owned();
    // Full lifecycle on site A: created + status + assign + link.
    let inc: Value = srv
        .client
        .post(format!("{}/sites/{aid}/incidents", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "title": "Audited case" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let iid = inc["id"].as_str().unwrap().to_owned();
    srv.client
        .post(format!("{}/sites/{aid}/incidents/{iid}/status", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "status": "investigating" }))
        .send()
        .await
        .unwrap();
    let users: Value = srv
        .client
        .get(format!("{}/users", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let analyst_id = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "analyst")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    srv.client
        .post(format!("{}/sites/{aid}/incidents/{iid}/assign", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "user_id": analyst_id }))
        .send()
        .await
        .unwrap();
    srv.client
        .post(format!("{}/sites/{aid}/incidents/{iid}/links", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "kind": "note", "note": "audit me" }))
        .send()
        .await
        .unwrap();
    // Noise case on site B (must NOT leak into A's view).
    srv.client
        .post(format!("{}/sites/{bid}/incidents", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "title": "Foreign case" }))
        .send()
        .await
        .unwrap();

    let trail: Value = srv
        .client
        .get(format!("{}/sites/{aid}/audit?limit=50", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let actions: Vec<&str> = trail
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["entity_id"] == iid)
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    for want in ["incident.created", "incident.status", "incident.assigned", "incident.linked"] {
        assert!(actions.contains(&want), "site audit shows {want}: {actions:?}");
    }
    assert!(trail.as_array().unwrap().iter().all(|e| {
        e["entity_id"] != serde_json::Value::Null
            || e["entity"] == "snapshot"
            || e["entity"] == "retention"
            || e["entity"] == "demo"
    }), "no foreign rows leak");
    let other: Value = srv
        .client
        .get(format!("{}/sites/{bid}/audit?limit=50", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(other.as_array().unwrap().iter().any(|e| e["action"] == "incident.created"));
    assert!(other.as_array().unwrap().iter().all(|e| e["entity_id"] != iid));
}
