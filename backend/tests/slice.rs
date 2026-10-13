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
    // Deterministic PRNG: no extra deps, stable across runs.
    let mut seed: u64 = 0x9E3779B97F4A7C15;
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
