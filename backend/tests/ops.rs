//! ops tests.
mod common;
use common::*;

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
async fn assignable_directory_scoped_to_eligible_actives() {
    let srv = TestServer::spawn().await;
    let analyst = srv.login("analyst").await;
    let gate = srv.login("gate").await;
    let superadmin = srv.login("superadmin").await;
    // Analyst (incidents:write, no users:read) sees the roster; gate refused.
    let roster: Value = srv
        .client
        .get(format!("{}/users/assignable", srv.base))
        .bearer_auth(&analyst)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = roster
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["username"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"analyst"), "analyst lists self: {names:?}");
    assert!(!names.contains(&"gate"), "gate lacks incidents:write");
    assert!(roster.as_array().unwrap().iter().all(|u| u["failed_logins"].is_null()
        && u["locked_until"].is_null()
        && u["active"].is_null()), "minimal fields only");
    let res = srv
        .client
        .get(format!("{}/users/assignable", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    // Deactivated analysts vanish from the roster.
    let uid = users_id(&srv, &superadmin, "analyst").await;
    srv.client
        .post(format!("{}/users/{uid}/deactivate", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap();
    let roster: Value = srv
        .client
        .get(format!("{}/users/assignable", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!roster.as_array().unwrap().iter().any(|u| u["username"] == "analyst"));
    srv.client
        .post(format!("{}/users/{uid}/reactivate", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap();
}

async fn users_id(srv: &TestServer, superadmin: &str, username: &str) -> String {
    let users: Value = srv
        .client
        .get(format!("{}/users", srv.base))
        .bearer_auth(superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == username)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn stats_reflect_baseline() {
    let srv = TestServer::spawn().await;
    let commander = srv.login("commander").await;
    let res = srv
        .client
        .get(format!("{}/stats", srv.base))
        .bearer_auth(&commander)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let stats: Value = res.json().await.unwrap();
    assert!(stats["sites"].as_i64().unwrap() >= 1);
    assert!(stats["gates"].as_i64().unwrap() >= 1);
    assert!(stats["pending_kyc"].as_i64().unwrap() >= 0);
}

#[tokio::test]
async fn sla_sweeper_escalates_overdue_without_any_read() {
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;
    let site_res = srv.client.post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin).json(&json!({"name": format!("Sweeper Site {}", uuid::Uuid::new_v4()), "location": "Delhi"}))
        .send().await.unwrap();
    assert_eq!(site_res.status(), 200, "site create: {}", site_res.text().await.unwrap_or_default());
    let site: Value = site_res.json().await.unwrap();
    let case: Value = srv.client.post(format!("{}/sites/{}/incidents", srv.base, site["id"].as_str().unwrap()))
        .bearer_auth(&superadmin).json(&json!({"title": "Overdue case", "description": "d"}))
        .send().await.unwrap().json().await.unwrap();
    // Backdate SLA directly; nobody opens the list.
    let state = test_state().await;
    sqlx::query("UPDATE incidents SET sla_due_at = now() - interval '1 day' WHERE id = $1")
        .bind(case["id"].as_str().unwrap().parse::<uuid::Uuid>().unwrap())
        .execute(&state.pool).await.unwrap();

    let stamped = nigrani::api::escalate_overdue(&state.pool, &state.hub).await;
    assert!(stamped >= 1, "sweeper must stamp at least our case");
    let list: Value = srv.client.get(format!("{}/sites/{}/incidents", srv.base, site["id"].as_str().unwrap()))
        .bearer_auth(&superadmin).send().await.unwrap().json().await.unwrap();
    let row = list.as_array().unwrap().iter().find(|r| r["id"] == case["id"]).unwrap();
    assert!(row["escalated_at"].is_string(), "case now carries escalation stamp");
    // Audit row exists with system actor (NULL actor_id).
    let sys_audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'incident.escalated' AND actor IS NULL")
        .fetch_one(&state.pool).await.unwrap();
    assert!(sys_audit >= 1);
}

#[tokio::test]
async fn metrics_endpoint_counts_and_gauges() {
    let srv = TestServer::spawn().await;
    // Generate some traffic (one 2xx, one 4xx).
    let _ = srv.client.get(format!("{}/health", srv.base)).send().await.unwrap();
    let _ = srv.client.get(format!("{}/users", srv.base)).send().await.unwrap(); // 401
    let m = srv.client.get(format!("{}/metrics", srv.base)).send().await.unwrap();
    assert_eq!(m.status(), 200);
    let body = m.text().await.unwrap();
    assert!(body.contains("nigrani_requests_total{class=\"2xx\"}"), "{body}");
    assert!(body.contains("nigrani_rows_total{entity=\"users\"}"));
    assert!(body.contains("entries_24h"));
}
