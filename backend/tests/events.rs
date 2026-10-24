//! events tests.
mod common;
use common::*;

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

