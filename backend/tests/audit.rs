//! audit tests.
mod common;
use common::*;

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

