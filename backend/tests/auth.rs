//! auth tests.
mod common;
use common::*;

#[tokio::test]
async fn refresh_reuse_burns_session_family() {
    let srv = TestServer::spawn().await;
    // Two independent logins = two live refresh tokens for the same user.
    let first: Value = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": "analyst", "password": "password" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let second: Value = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": "analyst", "password": "password" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let r1 = first["refresh_token"].as_str().unwrap().to_owned();
    let r2 = second["refresh_token"].as_str().unwrap().to_owned();

    // Normal rotation of r1 succeeds…
    let res = srv
        .client
        .post(format!("{}/auth/refresh", srv.base))
        .json(&json!({ "refresh_token": r1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // …then replaying the revoked r1 is flagged as reuse…
    let res = srv
        .client
        .post(format!("{}/auth/refresh", srv.base))
        .json(&json!({ "refresh_token": r1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "refresh token reused");

    // …and the untouched r2 is burned too: the whole family is dead.
    let res = srv
        .client
        .post(format!("{}/auth/refresh", srv.base))
        .json(&json!({ "refresh_token": r2 }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn oversized_login_rejected() {
    let srv = TestServer::spawn().await;
    let res = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": "x".repeat(65), "password": "password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn auth_endpoints_rate_limited() {
    let srv = TestServer::spawn().await;
    let mut limited = false;
    for _ in 0..25 {
        let res = srv
            .client
            .post(format!("{}/auth/login", srv.base))
            .json(&json!({ "username": "nosuch", "password": "x" }))
            .send()
            .await
            .unwrap();
        if res.status() == 429 {
            limited = true;
            break;
        }
    }
    assert!(limited, "expected 429 within 25 rapid logins");
}

#[tokio::test]
async fn logout_revokes_token_and_family() {
    let srv = TestServer::spawn().await;
    // Two sessions for the same user.
    let first: Value = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": "gate", "password": "password" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let second: Value = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": "gate", "password": "password" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let r1 = first["refresh_token"].as_str().unwrap().to_owned();
    let r2 = second["refresh_token"].as_str().unwrap().to_owned();
    let access = second["access_token"].as_str().unwrap().to_owned();

    // Single logout kills only r1.
    let res = srv
        .client
        .post(format!("{}/auth/logout", srv.base))
        .json(&json!({ "refresh_token": r1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = srv
        .client
        .post(format!("{}/auth/refresh", srv.base))
        .json(&json!({ "refresh_token": r1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    // Logout-all kills r2 too.
    let res = srv
        .client
        .post(format!("{}/auth/logout/all", srv.base))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = srv
        .client
        .post(format!("{}/auth/refresh", srv.base))
        .json(&json!({ "refresh_token": r2 }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn login_lockout_triggers_and_unlocks() {
    let srv = TestServer::spawn().await;
    let superadmin = srv.login("superadmin").await;

    // Fresh victim via provisioning (SuperAdmin-only create).
    let name = format!("lockme_{}", uuid::Uuid::new_v4().to_string().replace('-', "")[..12].to_owned());
    let created: Value = srv
        .client
        .post(format!("{}/users", srv.base))
        .bearer_auth(&superadmin)
        .json(&json!({ "username": name, "password": "victim-password-1", "role": "GateOperator" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let uid = created["id"].as_str().unwrap().to_owned();
    let bad = |pw: &str| {
        let client = &srv.client;
        let base = srv.base.clone();
        let name = name.clone();
        let pw = pw.to_owned();
        async move {
            client
                .post(format!("{base}/auth/login"))
                .json(&json!({ "username": name, "password": pw }))
                .send()
                .await
                .unwrap()
                .status()
        }
    };

    // Four strikes: still plain 401s, counter climbs, no lock.
    for _ in 0..4 {
        assert_eq!(bad("wrong-password-1").await, 401);
    }
    // A success here resets the counter (proves the reset path).
    let res = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": name, "password": "victim-password-1" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let me: Value = res.json().await.unwrap();
    assert!(me["user"]["locked_until"].is_null());

    // Five consecutive failures → locked. Correct password now also 401.
    // Hold a live refresh token across the lock transition: fresh login
    // (counter is 0 after the reset above), then 5 strikes.
    let res = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": name, "password": "victim-password-1" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let live_refresh = body["refresh_token"].as_str().unwrap().to_owned();
    for _ in 0..5 {
        assert_eq!(bad("wrong-password-1").await, 401);
    }
    assert_eq!(bad("victim-password-1").await, 401, "locked: right password rejected");
    // Refresh rotation ends at lock (401), even with a pre-lock token.
    let res = srv
        .client
        .post(format!("{}/auth/refresh", srv.base))
        .json(&json!({ "refresh_token": live_refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401, "locked: refresh rotation refused");
    // Non-SuperAdmin unlock refused; self-unlock refused.
    let gate = srv.login("gate").await;
    let res = srv
        .client
        .post(format!("{}/users/{uid}/unlock", srv.base))
        .bearer_auth(&gate)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let res = srv
        .client
        .post(format!("{}/users/{uid}/unlock", srv.base))
        .bearer_auth(&superadmin)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    // Login works again after unlock.
    let res = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": name, "password": "victim-password-1" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

