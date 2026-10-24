//! forensics tests.
mod common;
use common::*;

fn ones(n: usize) -> Vec<f64> {
    vec![1.0; n]
}


#[tokio::test]
async fn forensics_enroll_search_incidents_heatmap() {
    let srv = TestServer::spawn().await;
    let analyst = srv.login("analyst").await;
    let gate = srv.login("gate").await;
    let superadmin = srv.login("superadmin").await;

    // Near-duplicate enrolls of a distinctive random direction (shared DB
    // may hold residue from other tests, so assert on tight distances).
    // Time-seeded PRNG: every run enrolls unique vectors so residue from
    // prior runs (cosine distance ~1.0 away) falls outside the threshold.
    // (A fixed seed re-enrolled identical vectors and poisoned later runs.)
    let mut seed: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64
        ^ 0x9E3779B97F4A7C15;
    let mut rand = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed as f64) / (u64::MAX as f64) - 0.5
    };
    let base: Vec<f64> = (0..512).map(|_| rand()).collect();
    let mut close = base.clone();
    close[0] += 1e-4;
    // Link enrolls to a fresh application: search hits carry application_id,
    // so residue from other runs (unlinked) cannot pollute assertions.
    let marker: Value = srv
        .client
        .post(format!("{}/kyc/applications", srv.base))
        .json(&json!({
            "full_name": format!("Vector {}", uuid::Uuid::new_v4()),
            "document_type": "pan",
            "document_number": format!("V-{}", uuid::Uuid::new_v4()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let marker_id = marker["id"].as_str().unwrap().to_owned();
    for payload in [base.clone(), close] {
        let res = srv
            .client
            .post(format!("{}/forensics/embeddings", srv.base))
            .bearer_auth(&analyst)
            .json(&json!({ "embedding": payload, "application_id": marker_id }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
    }
    // Wrong dims + gate role denied.
    let res = srv
        .client
        .post(format!("{}/forensics/embeddings", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "embedding": vec![1.0; 10] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let res = srv
        .client
        .post(format!("{}/forensics/search", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "embedding": ones(512) }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Search ranks the near-duplicates first, distant zero-vector excluded
    // by threshold (cosine distance 1.0 from ones-vector).
    let hits: Value = srv
        .client
        .post(format!("{}/forensics/search", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "embedding": base, "threshold": 0.5, "limit": 20 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hits = hits.as_array().unwrap();
    let ours: Vec<&Value> =
        hits.iter().filter(|h| h["application_id"].as_str() == Some(marker_id.as_str())).collect();
    assert_eq!(ours.len(), 2, "both linked enrolls returned");
    assert!(
        ours.iter().all(|h| h["distance"].as_f64().unwrap() < 1e-6),
        "linked near-duplicates rank at ~zero distance"
    );

    // Incident + heatmap on a fresh site.
    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Forensic {}", uuid::Uuid::new_v4()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "title": "Bag", "description": "unattended" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let list: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&analyst)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
    // Gate role cannot file incidents (lacks incidents:write).
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "title": "Nope" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let heat: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/heatmap", srv.base))
        .bearer_auth(&analyst)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(heat.as_array().unwrap().is_empty(), "no gates yet");
}

#[tokio::test]
async fn forensic_references_validate_before_write() {
    let srv = TestServer::spawn().await;
    let analyst = srv.login("analyst").await;
    let superadmin = srv.login("superadmin").await;
    let ghost = uuid::Uuid::new_v4().to_string();

    // Enroll with dangling references → 404s, not 500s.
    let ones: Vec<f32> = vec![1.0; 512];
    for (field, status) in [("entry_log_id", 404), ("application_id", 404)] {
        let res = srv
            .client
            .post(format!("{}/forensics/embeddings", srv.base))
            .bearer_auth(&analyst)
            .json(&serde_json::json!({ "embedding": ones, field: ghost }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), status, "{field} dangling");
    }

    // Incident with dangling suspect → 404.
    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Refcheck {}", uuid::Uuid::new_v4()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let site_id = site["id"].as_str().unwrap().to_owned();
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "title": "Ghost suspect", "suspect_application_id": ghost }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // Valid incident + cross-site entry link → 400; bogus embedding → 404.
    let inc: Value = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "title": "Refcase" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let iid = inc["id"].as_str().unwrap().to_owned();
    let other: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Otherside {}", uuid::Uuid::new_v4()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let other_id = other["id"].as_str().unwrap().to_owned();
    let g: Value = srv
        .client
        .post(format!("{}/sites/{other_id}/gates", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": "X1" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gate = srv.login("gate").await;
    let ev: Value = srv
        .client
        .post(format!("{}/sites/{other_id}/gates/{}/events", srv.base, g["id"].as_str().unwrap()))
        .bearer_auth(&gate)
        .json(&json!({ "direction": "entry", "method": "manual" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    for (kind, ref_id, want) in [
        ("entry", ev["id"].as_str().unwrap().to_owned(), 400),
        ("entry", ghost.clone(), 404),
        ("embedding", ghost.clone(), 404),
    ] {
        let res = srv
            .client
            .post(format!("{}/sites/{site_id}/incidents/{iid}/links", srv.base))
            .bearer_auth(&analyst)
            .json(&json!({ "kind": kind, "ref_id": ref_id, "note": "x" }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), want, "{kind}/{ref_id}");
    }
}

