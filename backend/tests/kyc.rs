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
    // Cards now carry the per-print serial + 90-day expiry (lazily minted).
    assert!(card["serial"].as_str().unwrap().starts_with("SG-"), "serial: {card}");
    assert!(card["expires_at"].is_string());

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

// --- card lifecycle (0017): expiry, serials, reissue, CRL ---

/// Submit + approve an application; returns its id.
async fn approve_application(srv: &TestServer, verifier: &str, name: &str) -> String {
    let app: Value = srv
        .client
        .post(format!("{}/kyc/applications", srv.base))
        .json(&json!({
            "full_name": name,
            "document_type": "press_id",
            "document_number": format!("LC-{}", uuid::Uuid::new_v4()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = app["id"].as_str().unwrap().to_owned();
    let res = srv
        .client
        .post(format!("{}/kyc/applications/{id}/decide", srv.base))
        .bearer_auth(verifier)
        .json(&json!({ "decision": "approved" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "approve {name}");
    id
}

async fn card(srv: &TestServer, verifier: &str, id: &str) -> Value {
    srv.client
        .get(format!("{}/kyc/applications/{id}/press-card", srv.base))
        .bearer_auth(verifier)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn scan(srv: &TestServer, gate: &str, card: &Value) -> Value {
    srv.client
        .post(format!("{}/kyc/verify", srv.base))
        .bearer_auth(gate)
        .json(card)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn find_entry<'a>(list: &'a Value, id: &str) -> Option<&'a Value> {
    list.as_array()
        .unwrap()
        .iter()
        .find(|e| e["application_id"] == id)
}

#[tokio::test]
async fn card_lifecycle_reissue_rotates_serial_and_supersedes_old() {
    let srv = TestServer::spawn().await;
    let verifier = srv.login("verifier").await;
    let gate = srv.login("gate").await;
    let id = approve_application(&srv, &verifier, "Rotating Rita").await;

    // First print lazily mints serial + 90-day expiry.
    let card1 = card(&srv, &verifier, &id).await;
    let serial1 = card1["serial"].as_str().unwrap();
    assert!(serial1.starts_with("SG-") && serial1.ends_with("-1"), "serial {serial1}");
    assert!(card1["expires_at"].is_string());
    assert_eq!(scan(&srv, &gate, &card1).await["reason"], "ok");

    // Reissue bumps print count, rotates serial, refreshes expiry.
    let res = srv
        .client
        .post(format!("{}/kyc/applications/{id}/reissue", srv.base))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let reissued: Value = res.json().await.unwrap();
    assert_eq!(reissued["card_print_count"], 2);
    let serial2 = reissued["card_serial"].as_str().unwrap();
    assert!(serial2.ends_with("-2") && serial2 != serial1, "rotated {serial2}");

    let card2 = card(&srv, &verifier, &id).await;
    assert_eq!(card2["serial"], reissued["card_serial"]);

    // Old card scans superseded; new card ok.
    let verdict = scan(&srv, &gate, &card1).await;
    assert_eq!(verdict["valid"], false);
    assert_eq!(verdict["reason"], "superseded");
    let verdict = scan(&srv, &gate, &card2).await;
    assert_eq!(verdict["valid"], true);
    assert_eq!(verdict["reason"], "ok");
}

#[tokio::test]
async fn card_lifecycle_expired_card_scan_reports_expired() {
    let srv = TestServer::spawn().await;
    let verifier = srv.login("verifier").await;
    let gate = srv.login("gate").await;
    let id = approve_application(&srv, &verifier, "Expiring Earl").await;
    let card1 = card(&srv, &verifier, &id).await;
    assert_eq!(scan(&srv, &gate, &card1).await["reason"], "ok");

    // Plant a past expiry directly on the row.
    let state = test_state().await;
    sqlx::query("UPDATE kyc_applications SET card_expires_at = now() - interval '1 day' WHERE id = $1")
        .bind(id.parse::<uuid::Uuid>().unwrap())
        .execute(&state.pool)
        .await
        .unwrap();

    let verdict = scan(&srv, &gate, &card1).await;
    assert_eq!(verdict["valid"], false);
    assert_eq!(verdict["reason"], "expired");
}

#[tokio::test]
async fn card_lifecycle_crl_lists_revoked_expired_superseded() {
    let srv = TestServer::spawn().await;
    let verifier = srv.login("verifier").await;
    let gate = srv.login("gate").await;

    // Revoked fixture: approve, print, revoke.
    let revoked_id = approve_application(&srv, &verifier, "Revoked Ray").await;
    let revoked_card = card(&srv, &verifier, &revoked_id).await;
    let res = srv
        .client
        .post(format!("{}/kyc/applications/{revoked_id}/revoke-card", srv.base))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Expired fixture: approve, print, backdate expiry via SQL.
    let expired_id = approve_application(&srv, &verifier, "Expired Eve").await;
    let expired_card = card(&srv, &verifier, &expired_id).await;
    let state = test_state().await;
    sqlx::query("UPDATE kyc_applications SET card_expires_at = now() - interval '1 day' WHERE id = $1")
        .bind(expired_id.parse::<uuid::Uuid>().unwrap())
        .execute(&state.pool)
        .await
        .unwrap();

    // Superseded fixture: approve, print, reissue.
    let superseded_id = approve_application(&srv, &verifier, "Superseded Sue").await;
    let old_card = card(&srv, &verifier, &superseded_id).await;
    let res = srv
        .client
        .post(format!("{}/kyc/applications/{superseded_id}/reissue", srv.base))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let res = srv
        .client
        .get(format!("{}/kyc/crl", srv.base))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let disposition = res.headers().get("content-disposition").unwrap().to_str().unwrap();
    assert!(disposition.starts_with("attachment; filename=\"crl-"), "disposition {disposition}");
    let crl: Value = res.json().await.unwrap();
    assert!(crl["generated_at"].is_string());
    let revoked = find_entry(&crl["revoked"], &revoked_id).expect("revoked entry");
    assert_eq!(revoked["serial"], revoked_card["serial"]);
    assert!(revoked["since"].is_string());
    let expired = find_entry(&crl["expired"], &expired_id).expect("expired entry");
    assert_eq!(expired["serial"], expired_card["serial"]);
    let superseded = find_entry(&crl["superseded"], &superseded_id).expect("superseded entry");
    assert_eq!(superseded["serial"], old_card["serial"]);
    // Gate role CAN export the CRL (offline kiosk cache — s2/G2).
    let res = srv
        .client
        .get(format!("{}/kyc/crl", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "gate operator fetches CRL for offline cache");
}

#[tokio::test]
async fn card_lifecycle_reissue_refuses_nonapproved_revoked_missing() {
    let srv = TestServer::spawn().await;
    let verifier = srv.login("verifier").await;
    let gate = srv.login("gate").await;
    let reissue = |id: String, token: String| {
        let client = &srv.client;
        let base = srv.base.clone();
        async move {
            client
                .post(format!("{base}/kyc/applications/{id}/reissue"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .status()
        }
    };

    // Pending and rejected applications carry no card.
    let submit = |name: &str| {
        let client = &srv.client;
        let base = srv.base.clone();
        let name = name.to_owned();
        async move {
            client
                .post(format!("{base}/kyc/applications"))
                .json(&json!({
                    "full_name": name,
                    "document_type": "press_id",
                    "document_number": format!("RI-{}", uuid::Uuid::new_v4()),
                }))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let pending = submit("Pending Pam").await;
    assert_eq!(
        reissue(pending["id"].as_str().unwrap().to_owned(), verifier.clone()).await,
        409
    );
    let rejected = submit("Rejected Rob").await;
    srv.client
        .post(format!("{}/kyc/applications/{}/decide", srv.base, rejected["id"].as_str().unwrap()))
        .bearer_auth(&verifier)
        .json(&json!({ "decision": "rejected", "note": "no press pass" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        reissue(rejected["id"].as_str().unwrap().to_owned(), verifier.clone()).await,
        409
    );

    // Revoked approved application: no fresh credentials.
    let revoked_id = approve_application(&srv, &verifier, "Revoked Ron").await;
    let res = srv
        .client
        .post(format!("{}/kyc/applications/{revoked_id}/revoke-card", srv.base))
        .bearer_auth(&verifier)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(reissue(revoked_id.clone(), verifier.clone()).await, 409);

    // Unknown id → 404; gate role lacks kyc:review → 403.
    assert_eq!(reissue(uuid::Uuid::new_v4().to_string(), verifier.clone()).await, 404);
    let live_id = approve_application(&srv, &verifier, "Live Lena").await;
    assert_eq!(reissue(live_id, gate).await, 403);
}

#[tokio::test]
async fn card_lifecycle_concurrent_first_prints_share_serial() {
    let srv = TestServer::spawn().await;
    let verifier = srv.login("verifier").await;
    let id = approve_application(&srv, &verifier, "Racing Rae").await;
    let print = || {
        let client = &srv.client;
        let url = format!("{}/kyc/applications/{id}/press-card", srv.base);
        let token = verifier.clone();
        async move { client.get(url).bearer_auth(token).send().await.unwrap().json::<Value>().await.unwrap() }
    };
    let (a, b) = tokio::join!(print(), print());
    assert_eq!(a["serial"], b["serial"], "concurrent prints reuse one serial");
    let state = test_state().await;
    let count: i32 = sqlx::query_scalar("SELECT card_print_count FROM kyc_applications WHERE id = $1")
        .bind(id.parse::<uuid::Uuid>().unwrap())
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "minted exactly once");
}


/// Fuzzy duplicates: near-identical name and fuzzy doc number flag the
/// application (ids + score only), exact doc block still applies, and the
/// queue shows the stored flags.
#[tokio::test]
async fn fuzzy_duplicates_flagged_not_blocked() {
    let srv = TestServer::spawn().await;
    let uniq = uuid::Uuid::new_v4().to_string()[..8].to_owned();
    // First application (decided, so it doesn't block the resubmission).
    let first: Value = srv.client.post(format!("{}/kyc/applications", srv.base))
        .json(&json!({ "full_name": format!("Rohini Verma {uniq}"), "organization": "PNN",
                       "document_type": "press_id", "document_number": format!("PN-{uniq}-1234") }))
        .send().await.unwrap().json().await.unwrap();
    let admin = srv.login("superadmin").await;
    let first_id = first["id"].as_str().unwrap().to_owned();
    let res = srv.client.post(format!("{}/kyc/applications/{}/decide", srv.base, first_id))
        .bearer_auth(&admin).json(&json!({ "decision": "approved" })).send().await.unwrap();
    assert_eq!(res.status(), 200);

    // Second: NAME one edit away, doc number differs by a digit → flagged.
    let second: Value = srv.client.post(format!("{}/kyc/applications", srv.base))
        .json(&json!({ "full_name": format!("Rohini Vermi {uniq}"), "organization": "PNN",
                       "document_type": "press_id", "document_number": format!("PN-{uniq}-1235") }))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(second["status"], "pending", "fuzzy match flags but never blocks");
    let flags = second["duplicates"].as_array().unwrap();
    assert!(flags.iter().any(|f| f["similar_id"] == first_id.as_str() && f["reason"] == "name"),
            "name flagged: {flags:?}");
    // Distinct applicant: no flags.
    let third: Value = srv.client.post(format!("{}/kyc/applications", srv.base))
        .json(&json!({ "full_name": format!("Zubin Mehta {uniq}"), "document_type": "press_id",
                       "document_number": format!("ZZ-99-{uniq}") }))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(third["duplicates"].as_array().unwrap().len(), 0);

    // Queue carries the stored flags (search by the unique name — the
    // unfiltered page is oldest-first and saturated in the shared test DB).
    let queue: Value = srv.client.get(format!("{}/kyc/applications?status=pending&q={uniq}", srv.base))
        .bearer_auth(&admin).send().await.unwrap().json().await.unwrap();
    let row = queue.as_array().unwrap().iter().find(|r| r["id"] == second["id"]).unwrap();
    assert!(row["duplicates"].as_array().unwrap().iter().any(|f| f["similar_id"] == first_id.as_str()));

    // Exact pending duplicate still blocks (409) — flags don't weaken the block.
    let res = srv.client.post(format!("{}/kyc/applications", srv.base))
        .json(&json!({ "full_name": format!("Someone Else {uniq}"), "document_type": "press_id",
                       "document_number": format!("PN-{uniq}-1235") }))
        .send().await.unwrap();
    assert_eq!(res.status(), 409);
}

/// Photo-hash duplicates: same photo bytes under a different name flag with
/// reason=photo; oversized/malformed photos are refused.
#[tokio::test]
async fn photo_hash_duplicates_flagged() {
    let srv = TestServer::spawn().await;
    let uniq = uuid::Uuid::new_v4().to_string()[..8].to_owned();
    // 1x1 PNG bytes, base64 (deterministic tiny photo).
    let png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
    let photo = format!("data:image/png;base64,{png}");
    let first: Value = srv.client.post(format!("{}/kyc/applications", srv.base))
        .json(&json!({ "full_name": format!("Photo A {uniq}"), "document_type": "aadhaar",
                       "document_number": format!("AA-1-{uniq}"), "photo_url": photo }))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(first["status"], "pending");
    // Different name + document, SAME photo → photo flag.
    let second: Value = srv.client.post(format!("{}/kyc/applications", srv.base))
        .json(&json!({ "full_name": format!("Photo B {uniq}"), "document_type": "pan",
                       "document_number": format!("PN-2-{uniq}"), "photo_url": photo }))
        .send().await.unwrap().json().await.unwrap();
    let flags = second["duplicates"].as_array().unwrap();
    assert!(flags.iter().any(|f| f["similar_id"] == first["id"] && f["reason"] == "photo" && f["score"] == 1.0),
            "photo flagged: {flags:?}");
    // Malformed and oversized photos are refused cleanly.
    let res = srv.client.post(format!("{}/kyc/applications", srv.base))
        .json(&json!({ "full_name": "Bad photo", "document_type": "aadhaar",
                       "document_number": format!("AA-3-{uniq}"), "photo_url": "data:image/png;base64,!!!not-base64!!!" }))
        .send().await.unwrap();
    assert_eq!(res.status(), 400);
    let big = format!("data:image/png;base64,{}", "A".repeat(3 * 1024 * 1024));
    let res = srv.client.post(format!("{}/kyc/applications", srv.base))
        .json(&json!({ "full_name": "Big photo", "document_type": "aadhaar",
                       "document_number": format!("AA-4-{uniq}"), "photo_url": big }))
        .send().await.unwrap();
    // The 2 MB axum body limit intercepts before the handler: 413 is a
    // clean refusal too.
    assert_eq!(res.status(), 413);
}

#[tokio::test]
async fn card_format_v0_legacy_payloads_verify_again() {
    let srv = TestServer::spawn().await;
    let verifier = srv.login("verifier").await;
    let gate = srv.login("gate").await;
    let name = "Legacy Lata";
    let id = approve_application(&srv, &verifier, name).await;
    let state = test_state().await;

    // Legacy recipe (pre-0017): HMAC over (id, name, org, issued_at).
    let issued_at = 1_700_000_000i64;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use base64::Engine as _;
    let mut mac = Hmac::<Sha256>::new_from_slice(&state.jwt_secret).unwrap();
    mac.update(id.parse::<uuid::Uuid>().unwrap().as_bytes());
    mac.update(name.as_bytes());
    mac.update("".as_bytes()); // organization empty
    mac.update(issued_at.to_be_bytes().as_ref());
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    let legacy = json!({
        "application_id": id, "full_name": name, "organization": "",
        "issued_at": "2023-11-14T22:13:20Z", "signature": sig,
    });
    assert_eq!(scan(&srv, &gate, &legacy).await["reason"], "ok");

    // One flipped signature byte -> forged.
    let mut forged = legacy.clone();
    forged["signature"] = json!(format!("{}A", &sig[..sig.len() - 1]));
    assert_eq!(scan(&srv, &gate, &forged).await["reason"], "bad_signature");

    // Revocation still bites a legacy card.
    sqlx::query("UPDATE kyc_applications SET card_revoked_at = now() WHERE id = $1")
        .bind(id.parse::<uuid::Uuid>().unwrap())
        .execute(&state.pool).await.unwrap();
    assert_eq!(scan(&srv, &gate, &legacy).await["reason"], "revoked");

    // Current v1 cards still scan ok (mint one on a fresh application).
    let id2 = approve_application(&srv, &verifier, "Modern Mohan").await;
    let card1 = card(&srv, &verifier, &id2).await;
    assert_eq!(card1["v"], 1);
}

#[tokio::test]
async fn crl_is_fetchable_by_gate_operator_for_offline_cache() {
    let srv = TestServer::spawn().await;
    let gate = srv.login("gate").await;
    let res = srv.client.get(format!("{}/kyc/crl", srv.base)).bearer_auth(&gate).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body.get("revoked").is_some());
}
