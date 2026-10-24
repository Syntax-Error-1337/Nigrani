//! retention tests.
mod common;
use common::*;

#[tokio::test]
async fn retention_purge_and_export() {
    let _guard = RETENTION_LOCK.lock().await;
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

    // Purge removes exactly the expired rows (delta-counted — other test
    // binaries share this table) and reports counts.
    let expired_before: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM face_embeddings WHERE captured_at < now() - interval '1 day'")
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
    assert_eq!(report["purged"]["face_embeddings"], expired_before.0);
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
    // s36: gates carry archived_at (null when live), logs carry holder
    // slots (null on an empty site — keys present, values null).
    assert!(export["gates"].as_array().unwrap().is_empty());
    assert!(export["entry_logs"].as_array().unwrap().is_empty());
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
async fn purge_preview_mirrors_real_run() {
    let _guard = RETENTION_LOCK.lock().await;
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;
    let gate = srv.login("gate").await;
    // Non-SuperAdmin refused.
    let res = srv
        .client
        .post(format!("{}/admin/retention/preview", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    // Tighten embeddings to force exactly one doomed row.
    srv.client
        .post(format!("{}/admin/retention/policies/face_embeddings", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "retain_days": 1 }))
        .send()
        .await
        .unwrap();
    let state = test_state().await;
    let old_vec = format!("[{}]", vec!["0.5"; 512].join(","));
    sqlx::query(
        "INSERT INTO face_embeddings (embedding, captured_at) VALUES ($1::vector, now() - interval '5 days')",
    )
    .bind(&old_vec)
    .execute(&state.pool)
    .await
    .unwrap();
    let preview: Value = srv
        .client
        .post(format!("{}/admin/retention/preview", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(preview["dry_run"], true);
    let predicted = preview["purged"]["face_embeddings"].as_i64().unwrap();
    assert!(predicted >= 1, "preview sees the doomed row");
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
    assert_eq!(report["purged"]["face_embeddings"], predicted, "real run matches preview");
    let again: Value = srv
        .client
        .post(format!("{}/admin/retention/preview", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(again["purged"]["face_embeddings"], 0, "post-run preview is zero");
    srv.client
        .post(format!("{}/admin/retention/policies/face_embeddings", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "retain_days": 180 }))
        .send()
        .await
        .unwrap();
}

