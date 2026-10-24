//! occupancy trends + surge alerting tests.
mod common;
use common::*;

/// Fixture: site + gate, returns ids.
async fn mk_site_gate(srv: &TestServer, token: &str, label: &str) -> (String, String) {
    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(token)
        .json(&json!({ "name": format!("{label} {}", uuid::Uuid::new_v4()), "location": "Test" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();
    let gate: Value = srv
        .client
        .post(format!("{}/sites/{site_id}/gates", srv.base))
        .bearer_auth(token)
        .json(&json!({ "name": "G1" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (site_id, gate["id"].as_str().unwrap().to_owned())
}

#[tokio::test]
async fn trends_buckets_beyond_24h() {
    let srv = TestServer::spawn().await;
    let admin = srv.login("superadmin").await;
    let (site_id, gate_id) = mk_site_gate(&srv, &admin, "Trend").await;

    // Two entries now, one backdated 71h (inside the 72h window, outside 24h).
    let state = test_state().await;
    for _ in 0..2 {
        srv.client
            .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
            .bearer_auth(&admin)
            .json(&json!({ "direction": "entry", "method": "manual" }))
            .send()
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO entry_logs (gate_id, direction, method, recorded_by, recorded_at) VALUES ($1, 'entry', 'manual', $2, now() - interval '71 hours')")
        .bind(uuid::Uuid::parse_str(&gate_id).unwrap())
        .bind(sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM users WHERE username = 'superadmin'").fetch_one(&state.pool).await.unwrap())
        .execute(&state.pool)
        .await
        .unwrap();

    // 72h window: 3 entries across 2+ hour buckets (now + backdated).
    let trends: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/trends?hours=72", srv.base))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let buckets = trends.as_array().unwrap();
    let total: i64 = buckets.iter().map(|b| b["entries"].as_i64().unwrap()).sum();
    assert_eq!(total, 3, "72h window includes the backdated row");
    assert!(buckets.len() >= 2, "separate hour buckets for now and 3d ago");

    // Default window (24h) excludes the backdated row.
    let trends24: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/trends", srv.base))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let total24: i64 = trends24.as_array().unwrap().iter().map(|b| b["entries"].as_i64().unwrap()).sum();
    assert_eq!(total24, 2);

    // Window clamp: absurd hours are accepted but bounded, not an error.
    let res = srv.client.get(format!("{}/sites/{site_id}/trends?hours=99999", srv.base)).bearer_auth(&admin).send().await.unwrap();
    assert_eq!(res.status(), 200);

    // Cross-role read: VerificationOfficer holds gates:read.
    let verifier = srv.login("verifier").await;
    let res = srv.client.get(format!("{}/sites/{site_id}/trends", srv.base)).bearer_auth(&verifier).send().await.unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn surge_threshold_triggers_once_per_hour() {
    let srv = TestServer::spawn().await;
    let admin = srv.login("superadmin").await;
    let gate_tok = srv.login("gate").await;
    let (site_id, gate_id) = mk_site_gate(&srv, &admin, "Surge").await;

    // Set threshold=2 (entries/hour).
    let set: Value = srv
        .client
        .post(format!("{}/sites/{site_id}/surge", srv.base))
        .bearer_auth(&admin)
        .json(&json!({ "threshold": 2 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(set["threshold"], 2);
    // Validation: 0 and negative refused.
    let bad = srv.client.post(format!("{}/sites/{site_id}/surge", srv.base)).bearer_auth(&admin).json(&json!({ "threshold": 0 })).send().await.unwrap();
    assert_eq!(bad.status(), 400);

    // Crossing 1: under threshold, no alert.
    // Crossing 2: at threshold, no alert (must EXCEED).
    // Crossings 3..4: exceed → exactly ONE alert for the hour.
    for _ in 0..4 {
        srv.client
            .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
            .bearer_auth(&gate_tok)
            .json(&json!({ "direction": "entry", "method": "manual" }))
            .send()
            .await
            .unwrap();
    }
    let surge: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/surge", srv.base))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let alerts = surge["alerts"].as_array().cloned().unwrap_or_else(|| {
        panic!("surge GET body: {surge}");
    });
    assert_eq!(alerts.len(), 1, "one alert per gate-hour");
    // The alert records the moment of crossing: the 3rd entry (first over
    // the 2/hour threshold), not the final count.
    assert_eq!(alerts[0]["count"], 3);
    assert_eq!(alerts[0]["threshold"], 2);
    assert_eq!(alerts[0]["gate_name"], "G1");

    // A further crossing the same hour does not add alerts.
    srv.client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
        .bearer_auth(&gate_tok)
        .json(&json!({ "direction": "entry", "method": "manual" }))
        .send()
        .await
        .unwrap();
    let surge: Value = srv.client.get(format!("{}/sites/{site_id}/surge", srv.base)).bearer_auth(&admin).send().await.unwrap().json().await.unwrap();
    assert_eq!(surge["alerts"].as_array().unwrap().len(), 1, "deduped per hour");

    // Exits never trigger; clearing the threshold stops future alerts.
    srv.client.post(format!("{}/sites/{site_id}/surge", srv.base)).bearer_auth(&admin).json(&json!({ "threshold": null })).send().await.unwrap();
    let cleared: Value = srv.client.get(format!("{}/sites/{site_id}/surge", srv.base)).bearer_auth(&admin).send().await.unwrap().json().await.unwrap();
    assert_eq!(cleared["threshold"], serde_json::Value::Null);
    let n_before = cleared["alerts"].as_array().unwrap().len();
    srv.client.post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base)).bearer_auth(&gate_tok).json(&json!({ "direction": "exit", "method": "manual" })).send().await.unwrap();
    let after: Value = srv.client.get(format!("{}/sites/{site_id}/surge", srv.base)).bearer_auth(&admin).send().await.unwrap().json().await.unwrap();
    assert_eq!(after["alerts"].as_array().unwrap().len(), n_before as usize, "no new alerts while disabled");

    // Permission: gate operator cannot set the threshold.
    let res = srv.client.post(format!("{}/sites/{site_id}/surge", srv.base)).bearer_auth(&gate_tok).json(&json!({ "threshold": 3 })).send().await.unwrap();
    assert_eq!(res.status(), 403);
}

/// Surge fans out live on the event stream.
#[tokio::test]
async fn surge_fans_out_on_stream() {
    use futures_util::StreamExt;
    let srv = TestServer::spawn().await;
    let gate_tok = srv.login("gate").await;
    let admin = srv.login("superadmin").await;
    let (site_id, gate_id) = mk_site_gate(&srv, &admin, "SurgeStream").await;
    srv.client
        .post(format!("{}/sites/{site_id}/surge", srv.base))
        .bearer_auth(&admin)
        .json(&json!({ "threshold": 1 }))
        .send()
        .await
        .unwrap();

    let url = format!("{}/events?token={gate_tok}", srv.base.replace("http", "ws"));
    let (mut sock, _) = tokio_tungstenite::connect_async(&url).await.expect("ws");

    for _ in 0..2 {
        srv.client
            .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
            .bearer_auth(&gate_tok)
            .json(&json!({ "direction": "entry", "method": "manual" }))
            .send()
            .await
            .unwrap();
    }

    // Drain until the surge event appears (crossing arrives first).
    let mut seen = false;
    for _ in 0..10 {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), sock.next())
            .await
            .expect("event in time")
            .expect("ws message")
            .expect("text");
        let text = msg.into_text().expect("text");
        let v: Value = serde_json::from_str(&text).unwrap();
        if v["kind"] == "surge" {
            assert_eq!(v["count"], 2);
            assert_eq!(v["threshold"], 1);
            assert_eq!(v["site_id"], site_id);
            seen = true;
            break;
        }
    }
    assert!(seen, "surge event observed on the stream");
}
