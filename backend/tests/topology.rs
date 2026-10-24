//! topology tests.
mod common;
use common::*;

#[tokio::test]
async fn list_pagination_and_offset_cap() {
    let srv = TestServer::spawn().await;
    let gate = srv.login("gate").await;
    // limit honored
    let one: Value = srv
        .client
        .get(format!("{}/sites?limit=1", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(one.as_array().unwrap().len(), 1);
    // offset pages past the first row (unique prefix isolates the test
    // from shared-DB residue; a bare count would saturate the limit cap).
    let tag = format!("Pagetest{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    for suffix in ["A", "B", "C"] {
        let superadmin = srv.login("superadmin").await;
        srv.client
            .post(format!("{}/sites", srv.base))
            .bearer_auth(&superadmin)
            .json(&json!({ "name": format!("{tag}{suffix}") }))
            .send()
            .await
            .unwrap();
    }
    let all: Value = srv
        .client
        .get(format!("{}/sites?q={tag}&limit=200", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(all.as_array().unwrap().len(), 3);
    let rest: Value = srv
        .client
        .get(format!("{}/sites?q={tag}&limit=200&offset=1", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rest.as_array().unwrap().len(), 2);
    // offset cap enforced
    let res = srv
        .client
        .get(format!("{}/sites?offset=10001", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn topology_retirement_archive_restore_guards() {
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;
    let gate = srv.login("gate").await;

    let site: Value = srv
        .client
        .post(format!("{}/sites", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": format!("Retire {}", uuid::Uuid::new_v4()) }))
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
        .json(&json!({ "name": "G1" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gate_id = g["id"].as_str().unwrap().to_owned();

    // Site with a live gate refuses to archive.
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/archive/archive", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 409);

    // Archive the gate: crossings go 410, lists hide it.
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/archive/archive", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "direction": "entry", "method": "manual" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 410);
    let gates: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/gates", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(gates.as_array().unwrap().is_empty());
    let gates: Value = srv
        .client
        .get(format!("{}/sites/{site_id}/gates?include=archived", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(gates.as_array().unwrap().len(), 1);

    // Now the site archives; incidents + gates-create go 410 there.
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/archive/archive", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let analyst = srv.login("analyst").await;
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/incidents", srv.base))
        .bearer_auth(&analyst)
        .json(&json!({ "title": "Nope" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 410);
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "name": "G2" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 410);

    // Gate role cannot archive (needs gates:write).
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/archive/restore", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    // Restore both: crossings flow again.
    for (url, want) in [
        (format!("{}/sites/{site_id}/gates/{gate_id}/archive/restore", srv.base), 200),
        (format!("{}/sites/{site_id}/archive/restore", srv.base), 200),
    ] {
        let res = srv.client.post(url).bearer_auth(&superadmin).send().await.unwrap();
        assert_eq!(res.status(), want);
    }
    let res = srv
        .client
        .post(format!("{}/sites/{site_id}/gates/{gate_id}/events", srv.base))
        .bearer_auth(&gate)
        .json(&json!({ "direction": "entry", "method": "manual" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

