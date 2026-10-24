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


#[tokio::test]
async fn retention_purge_deletes_s3_objects_for_erasure() {
    // Real snapshot store against the compose/CI LocalStack.
    std::env::set_var("S3_ENDPOINT", "http://127.0.0.1:4566");
    std::env::set_var("S3_BUCKET", "nigrani-snapshots");
    std::env::set_var("AWS_REGION", "us-east-1");
    std::env::set_var("AWS_ACCESS_KEY_ID", "nigrani");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "nigrani-secret-key");
    let store = nigrani::infrastructure::storage::SnapshotStore::from_env().await.unwrap();
    let mut state = test_state().await;
    use uuid::Uuid;
    state.snapshots = Some(store.clone());

    let key = format!("erasure/{}/a.jpg", uuid::Uuid::new_v4());
    store.put_jpeg(&key, vec![0xFFu8; 16]).await.unwrap();
    // A crossing log referencing the key, aged past a 30-day entry_logs policy.
    let (uid,): (Uuid,) = sqlx::query_as("SELECT id FROM users WHERE username = 'superadmin'")
        .fetch_one(&state.pool).await.unwrap();
    let (site_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO sites (name, location) VALUES ('Erasure Site', 'X') ON CONFLICT (name) DO UPDATE SET location = 'X' RETURNING id")
        .fetch_one(&state.pool).await.unwrap();
    let (gate_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO gates (site_id, name, direction) VALUES ($1, 'G1', 'entry')
         ON CONFLICT (site_id, name) DO UPDATE SET direction = 'entry' RETURNING id")
        .bind(site_id).fetch_one(&state.pool).await.unwrap();
    sqlx::query(
        "INSERT INTO entry_logs (gate_id, direction, method, snapshot_key, recorded_by, recorded_at)
         VALUES ($1, 'entry', 'manual', $2, $3, now() - interval '400 days')",
    )
    .bind(gate_id)
    .bind(&key)
    .bind(uid)
    .execute(&state.pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO retention_policies (entity, retain_days) VALUES ('entry_logs', 30) ON CONFLICT (entity) DO UPDATE SET retain_days = 30")
        .execute(&state.pool).await.unwrap();

    let srv = TestServer::serve(state).await;
    let sa = srv.login("superadmin").await;
    let report: Value = srv.client.post(format!("{}/admin/retention/run", srv.base))
        .bearer_auth(&sa).send().await.unwrap().json().await.unwrap();
    assert!(report["snapshots_deleted"].as_i64().unwrap() >= 1, "purge must delete the dereferenced object");
    // The object is GONE from S3 (erasure, not just dereference).
    let gone = store.exists(&key).await.unwrap();
    assert!(!gone, "S3 object must be deleted after purge");
}

#[tokio::test]
async fn daily_report_csv_counts_crossings() {
    let srv = TestServer::spawn().await;
    let sa = srv.login("superadmin").await;
    let site: Value = srv.client.post(format!("{}/sites", srv.base))
        .bearer_auth(&sa).json(&json!({"name": format!("Report {}", uuid::Uuid::new_v4()), "location": "x"}))
        .send().await.unwrap().json().await.unwrap();
    let sid = site["id"].as_str().unwrap();
    let gate: Value = srv.client.post(format!("{}/sites/{sid}/gates", srv.base))
        .bearer_auth(&sa).json(&json!({"name": "RG", "direction": "both"}))
        .send().await.unwrap().json().await.unwrap();
    let gid = gate["id"].as_str().unwrap();
    for d in ["entry", "entry", "exit"] {
        srv.client.post(format!("{}/sites/{sid}/gates/{gid}/events", srv.base))
            .bearer_auth(&sa).json(&json!({"direction": d, "method": "manual"}))
            .send().await.unwrap();
    }
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let res = srv.client.get(format!("{}/sites/{sid}/report.csv?date={today}", srv.base))
        .bearer_auth(&sa).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let csv = res.text().await.unwrap();
    assert!(csv.contains("gate,card_entries,manual_entries,exits"));
    let row = csv.lines().nth(1).unwrap();
    assert!(row.ends_with("0,2,1"), "got: {row}");
    // Bad date refused.
    let bad = srv.client.get(format!("{}/sites/{sid}/report.csv?date=nope", srv.base))
        .bearer_auth(&sa).send().await.unwrap();
    assert_eq!(bad.status(), 400);
}
