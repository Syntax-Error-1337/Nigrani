//! incidents tests.
mod common;
use common::*;

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
    // Shared dev DB carries rows from other sessions; assert this run's
    // purge matches the aged rows actually present (ours among them).
    let aged_links: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM incident_links WHERE added_at < now() - interval '1 day'",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap();
    let aged_incidents: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM incidents WHERE created_at < now() - interval '1 day'",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap();
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
    assert!(aged_incidents >= 1 && aged_links >= 1, "backdated rows counted as aged: incidents={aged_incidents} links={aged_links}");
    for entity in ["incidents", "incident_links"] {
        srv.client
            .post(format!("{}/admin/retention/policies/{entity}", srv.base))
            .bearer_auth(&superadmin)
            .json(&json!({ "retain_days": 365 }))
            .send()
            .await
            .unwrap();
    }
    assert_eq!(report["purged"]["incident_links"], aged_links);
    assert_eq!(report["purged"]["incidents"], aged_incidents);
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


/// SLA: new cases get a 72h due stamp; an overdue open case escalates
/// lazily on the first list read (once), audited and fanned out.
#[tokio::test]
async fn sla_escalation_lazily_marks_overdue() {
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;
    let site: Value = srv.client.post(format!("{}/sites", srv.base)).bearer_auth(&superadmin)
        .json(&json!({ "name": format!("SLA {}", uuid::Uuid::new_v4()) })).send().await.unwrap().json().await.unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();
    let inc: Value = srv.client.post(format!("{}/sites/{site_id}/incidents", srv.base)).bearer_auth(&superadmin)
        .json(&json!({ "title": "SLA case" })).send().await.unwrap().json().await.unwrap();
    let iid = inc["id"].as_str().unwrap().to_owned();
    // Fresh case: stamped, not overdue.
    assert!(inc["sla_due_at"].as_str().is_some());
    assert_eq!(inc["overdue"], false);

    // Backdate the SLA past due.
    let state = test_state().await;
    sqlx::query("UPDATE incidents SET sla_due_at = now() - interval '1 hour' WHERE id = $1")
        .bind(uuid::Uuid::parse_str(&iid).unwrap())
        .execute(&state.pool).await.unwrap();

    let list: Value = srv.client.get(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&superadmin).send().await.unwrap().json().await.unwrap();
    let row = list.as_array().unwrap().iter().find(|r| r["id"] == inc["id"]).unwrap();
    assert_eq!(row["overdue"], true);
    assert!(row["escalated_at"].as_str().is_some(), "escalated on first read");

    // Idempotent: second read keeps the same stamp, no duplicate escalation.
    let list2: Value = srv.client.get(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&superadmin).send().await.unwrap().json().await.unwrap();
    let row2 = list2.as_array().unwrap().iter().find(|r| r["id"] == inc["id"]).unwrap();
    assert_eq!(row2["escalated_at"], row["escalated_at"]);

    // Audit chain records the escalation.
    let audit: Value = srv.client.get(format!("{}/audit?limit=200", srv.base))
        .bearer_auth(&superadmin).send().await.unwrap().json().await.unwrap();
    assert!(audit.as_array().unwrap().iter().any(|a| a["action"] == "incident.escalated" && a["entity_id"] == inc["id"]));
}

/// Merge moves evidence links, closes and tombstones the absorbed case;
/// merged cases refuse mutations; chains and cross-site merges refused.
#[tokio::test]
async fn merge_moves_links_and_readonly_tombstones() {
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;
    let mk = |n: String| n;
    let _ = mk(String::new());

    async fn mk_site(srv: &TestServer, superadmin: &str, name: String) -> String {
        let s: Value = srv.client.post(format!("{}/sites", srv.base)).bearer_auth(superadmin)
            .json(&json!({ "name": name })).send().await.unwrap().json().await.unwrap();
        s["id"].as_str().unwrap().to_owned()
    }
    async fn mk_inc(srv: &TestServer, superadmin: &str, site: &str, title: &str) -> String {
        let v: Value = srv.client.post(format!("{}/sites/{site}/incidents", srv.base)).bearer_auth(superadmin)
            .json(&json!({ "title": title })).send().await.unwrap().json().await.unwrap();
        v["id"].as_str().unwrap().to_owned()
    }
    let site = mk_site(&srv, &superadmin, format!("Merge {}", uuid::Uuid::new_v4())).await;
    let other = mk_site(&srv, &superadmin, format!("Else {}", uuid::Uuid::new_v4())).await;
    let survivor = mk_inc(&srv, &superadmin, &site, "Survivor").await;
    let absorbed = mk_inc(&srv, &superadmin, &site, "Absorbed").await;
    let foreign = mk_inc(&srv, &superadmin, &other, "Foreign").await;
    let merged_early = mk_inc(&srv, &superadmin, &site, "Already merged").await;

    // Evidence on the absorbed case.
    let link: Value = srv.client.post(format!("{}/sites/{site}/incidents/{absorbed}/links", srv.base))
        .bearer_auth(&superadmin).json(&json!({ "kind": "note", "note": "saw it happen" }))
        .send().await.unwrap().json().await.unwrap();
    let link_id = link["id"].as_str().unwrap().to_owned();

    // Refusals first.
    let res = srv.client.post(format!("{}/sites/{site}/incidents/{absorbed}/merge", srv.base))
        .bearer_auth(&superadmin).json(&json!({ "into": absorbed })).send().await.unwrap();
    assert_eq!(res.status(), 400, "self-merge");
    let res = srv.client.post(format!("{}/sites/{site}/incidents/{absorbed}/merge", srv.base))
        .bearer_auth(&superadmin).json(&json!({ "into": foreign })).send().await.unwrap();
    assert_eq!(res.status(), 404, "cross-site target invisible");
    // Merge the helper case first, then prove chains are refused.
    let res = srv.client.post(format!("{}/sites/{site}/incidents/{merged_early}/merge", srv.base))
        .bearer_auth(&superadmin).json(&json!({ "into": survivor })).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let res = srv.client.post(format!("{}/sites/{site}/incidents/{absorbed}/merge", srv.base))
        .bearer_auth(&superadmin).json(&json!({ "into": merged_early })).send().await.unwrap();
    assert_eq!(res.status(), 409, "merge into a merged case refused");

    // Real merge.
    let res = srv.client.post(format!("{}/sites/{site}/incidents/{absorbed}/merge", srv.base))
        .bearer_auth(&superadmin).json(&json!({ "into": survivor })).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let merged = res.json::<Value>().await.unwrap();
    assert_eq!(merged["merged_into"], survivor.as_str());
    assert_eq!(merged["status"], "closed");

    // Links moved to the survivor.
    let links: Value = srv.client.get(format!("{}/sites/{site}/incidents/{survivor}/links", srv.base))
        .bearer_auth(&superadmin).send().await.unwrap().json().await.unwrap();
    assert!(links.as_array().unwrap().iter().any(|l| l["id"] == link_id.as_str()), "link moved");

    // Absorbed case refuses mutations.
    let res = srv.client.post(format!("{}/sites/{site}/incidents/{absorbed}/status", srv.base))
        .bearer_auth(&superadmin).json(&json!({ "status": "investigating" })).send().await.unwrap();
    assert_eq!(res.status(), 409);
    let res = srv.client.post(format!("{}/sites/{site}/incidents/{absorbed}/links", srv.base))
        .bearer_auth(&superadmin).json(&json!({ "kind": "note", "note": "x" })).send().await.unwrap();
    assert_eq!(res.status(), 409);
    let res = srv.client.post(format!("{}/sites/{site}/incidents/{absorbed}/merge", srv.base))
        .bearer_auth(&superadmin).json(&json!({ "into": survivor })).send().await.unwrap();
    assert_eq!(res.status(), 409);
}

/// Courtroom pack: case + resolved evidence + audit slice with chain verdict.
#[tokio::test]
async fn courtroom_pack_carries_resolved_evidence() {
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;
    let site: Value = srv.client.post(format!("{}/sites", srv.base)).bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Pack {}", uuid::Uuid::new_v4()) })).send().await.unwrap().json().await.unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();
    let inc: Value = srv.client.post(format!("{}/sites/{site_id}/incidents", srv.base)).bearer_auth(&superadmin)
        .json(&json!({ "title": "Pack case" })).send().await.unwrap().json().await.unwrap();
    let iid = inc["id"].as_str().unwrap().to_owned();

    // A real crossing + note link.
    let gate: Value = srv.client.post(format!("{}/sites/{site_id}/gates", srv.base)).bearer_auth(&superadmin)
        .json(&json!({ "name": "G" })).send().await.unwrap().json().await.unwrap();
    let gid = gate["id"].as_str().unwrap().to_owned();
    let log: Value = srv.client.post(format!("{}/sites/{site_id}/gates/{gid}/events", srv.base)).bearer_auth(&superadmin)
        .json(&json!({ "direction": "entry", "method": "manual" })).send().await.unwrap().json().await.unwrap();
    srv.client.post(format!("{}/sites/{site_id}/incidents/{iid}/links", srv.base)).bearer_auth(&superadmin)
        .json(&json!({ "kind": "entry", "ref_id": log["id"] })).send().await.unwrap();
    srv.client.post(format!("{}/sites/{site_id}/incidents/{iid}/links", srv.base)).bearer_auth(&superadmin)
        .json(&json!({ "kind": "note", "note": "witness statement" })).send().await.unwrap();

    let res = srv.client.get(format!("{}/sites/{site_id}/incidents/{iid}/pack", srv.base))
        .bearer_auth(&superadmin).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert!(res.headers().get("content-disposition").map(|v| v.to_str().unwrap().contains("attachment")).unwrap_or(false));
    let pack = res.json::<Value>().await.unwrap();
    assert_eq!(pack["incident"]["id"], iid.as_str());
    let evidence = pack["evidence"].as_array().unwrap();
    assert_eq!(evidence.len(), 2);
    assert!(evidence.iter().any(|e| e["kind"] == "entry" && e["entry"]["id"] == log["id"]), "crossing resolved");
    assert!(evidence.iter().any(|e| e["kind"] == "note" && e["note"] == "witness statement"));
    assert_eq!(pack["audit_verdict"]["ok"], true);
    assert!(pack["audit"].as_array().unwrap().iter().any(|a| a["action"] == "incident.created"));
    assert!(pack["exported_at"].as_str().is_some());

    // Permission: gate operator lacks incidents:write.
    let gate_tok = srv.login("gate").await;
    let res = srv.client.get(format!("{}/sites/{site_id}/incidents/{iid}/pack", srv.base))
        .bearer_auth(&gate_tok).send().await.unwrap();
    assert_eq!(res.status(), 403);
}
