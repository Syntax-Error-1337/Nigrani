//! kyc tests.
mod common;
use common::*;

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

    // Re-decide is a conflict (note supplied so the rejection-note
    // validation passes through to the immutability guard).
    let res = srv
        .client
        .post(format!("{}/kyc/applications/{id}/decide", srv.base))
        .bearer_auth(&verifier)
        .json(&json!({ "decision": "rejected", "note": "second thoughts" }))
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
    // Revoked credentials never re-print (JSON or PNG).
    for path in ["press-card", "press-card.png"] {
        let res = srv
            .client
            .get(format!("{}/kyc/applications/{app_id}/{path}", srv.base))
            .bearer_auth(&verifier)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 409, "re-print refused: {path}");
    }
}

#[tokio::test]
async fn rejection_requires_actionable_note() {
    let srv = TestServer::spawn().await;
    let verifier = srv.login("verifier").await;
    let mk = |name: &str| {
        let client = &srv.client;
        let base = srv.base.clone();
        let name = name.to_owned();
        async move {
            client
                .post(format!("{base}/kyc/applications"))
                .json(&json!({
                    "full_name": name,
                    "document_type": "pan",
                    "document_number": format!("N-{}", uuid::Uuid::new_v4()),
                }))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let pend = |id: &str, note: Option<&str>| {
        let client = &srv.client;
        let base = srv.base.clone();
        let verifier = verifier.clone();
        let id = id.to_owned();
        let note = note.map(str::to_owned);
        async move {
            let mut payload = serde_json::json!({ "decision": "rejected" });
            if let Some(n) = note {
                payload["note"] = serde_json::json!(n);
            }
            client
                .post(format!("{base}/kyc/applications/{id}/decide"))
                .bearer_auth(&verifier)
                .json(&payload)
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    // Missing, empty, and whitespace notes refused.
    for note in [None, Some(""), Some("   "), Some("ok")] {
        let app = mk("Noteless Nate").await;
        let id = app["id"].as_str().unwrap();
        assert_eq!(pend(id, note).await, 400, "note {note:?} refused");
    }
    // Actionable note decides; note round-trips on the row.
    let app = mk("Noted Nelly").await;
    let id = app["id"].as_str().unwrap().to_owned();
    assert_eq!(pend(&id, Some("document expired, re-apply with renewed ID")).await, 200);
    let queue: Value = srv
        .client
        .get(format!("{}/kyc/applications?status=rejected", srv.base))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = queue.as_array().unwrap().iter().find(|r| r["id"] == id).unwrap();
    assert_eq!(row["decision_note"], "document expired, re-apply with renewed ID");
    // Approvals still need no note.
    let app = mk("Approved Amy").await;
    let id = app["id"].as_str().unwrap().to_owned();
    let res = srv
        .client
        .post(format!("{}/kyc/applications/{id}/decide", srv.base))
        .bearer_auth(&verifier)
        .json(&json!({ "decision": "approved" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

