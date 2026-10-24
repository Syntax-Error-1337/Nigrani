//! gate tests.
mod common;
use common::*;

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
    assert!(entry["holder_name"].is_string(), "card crossing names its holder");
    assert!(entry["holder_org"].is_string());

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
    assert!(log[0]["holder_name"].is_null(), "manual crossing names nobody");
    assert_eq!(log[1]["method"], "press_card");
    assert!(log[1]["holder_name"].is_string(), "log list joins holder names");

    // s36: export mirrors the live shapes (holder identity + archived flags).
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
    let xlogs = export["entry_logs"].as_array().unwrap();
    assert_eq!(xlogs.len(), 2);
    let card_row = xlogs.iter().find(|r| r["method"] == "press_card").unwrap();
    assert!(card_row["holder_name"].is_string(), "export carries holder names");
    assert!(xlogs.iter().find(|r| r["method"] == "manual").unwrap()["holder_name"].is_null());
    let xgates = export["gates"].as_array().unwrap();
    assert_eq!(xgates.len(), 1);
    assert!(xgates[0].get("archived_at").is_some(), "export carries archived flag");
    assert!(xgates[0]["archived_at"].is_null(), "live gate exports null archived_at");
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
async fn snapshot_upload_rate_limited() {
    // Test server carries snapshots: None, so uploads fail closed BEFORE the
    // limiter matters... except middleware runs FIRST: the 429 must win over
    // the 500 once the quota burns. Upload tiny JPEGs (valid magic).
    let srv = TestServer::spawn().await;
    let gate = srv.login("gate").await;
    let jpeg: Vec<u8> = vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 16, 0x4A, 0x46, 0x49, 0x46];
    let mut limited = false;
    for _ in 0..35 {
        let res = srv
            .client
            .post(format!("{}/snapshots", srv.base))
            .bearer_auth(&gate)
            .header("Content-Type", "image/jpeg")
            .body(jpeg.clone())
            .send()
            .await
            .unwrap();
        if res.status() == 429 {
            limited = true;
            break;
        }
    }
    assert!(limited, "expected 429 within 35 rapid uploads");
}

#[tokio::test]
async fn gate_duty_assignment_flow() {
    let srv = TestServer::spawn().await;
    let commander = srv.login("commander").await;
    let verifier = srv.login("verifier").await;
    let superadmin = srv.login("superadmin").await;

    // Fixture site + gate.
    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Duty {}", uuid::Uuid::new_v4()) }))
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
        .bearer_auth(&commander)
        .json(&json!({ "name": "North A" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gate_id = gate_res["id"].as_str().unwrap().to_owned();

    // Non-staff user refused (analyst lacks entries:write).
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
    let find_user = |name: &str| {
        users
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["username"] == name)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/duty", srv.base))
        .bearer_auth(&commander)
        .json(&json!({ "user_id": find_user("analyst") }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);

    // Unknown user → 404.
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/duty", srv.base))
        .bearer_auth(&commander)
        .json(&json!({ "user_id": uuid::Uuid::new_v4().to_string() }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // Commander assigns the verifier.
    let verifier_id = find_user("verifier");
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/duty", srv.base))
        .bearer_auth(&commander)
        .json(&json!({ "user_id": verifier_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let duty: Value = res.json().await.unwrap();
    assert_eq!(duty["duty_officer"], verifier_id);
    assert_eq!(duty["duty_username"], "verifier");

    // Gate list carries the duty assignment.
    let gates: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/gates", srv.base))
        .bearer_auth(&commander)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = gates.as_array().unwrap().iter().find(|g| g["id"] == gate_id).unwrap();
    assert_eq!(row["duty_username"], "verifier");

    // Duty officer sees the gate on their roster.
    let roster: Value = srv
        .client
        .get(format!("{}/my/duty", srv.base))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let roster_row = roster
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["gate_id"] == gate_id)
        .expect("assigned gate in roster");
    assert_eq!(roster_row["site_name"], site["name"]);

    // Duty officer records a crossing (verifier now holds entries:write).
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
        .bearer_auth(&verifier)
        .json(&json!({ "direction": "entry", "method": "manual" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "verifier on duty records crossings");

    // Clear duty.
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/duty", srv.base))
        .bearer_auth(&commander)
        .json(&json!({ "user_id": null }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let cleared: Value = res.json().await.unwrap();
    assert!(cleared["duty_officer"].is_null());
}

