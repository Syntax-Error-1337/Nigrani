//! auth tests.
mod common;
use common::*;

#[tokio::test]
async fn refresh_reuse_burns_session_family() {
    let srv = TestServer::spawn().await;
    // Two independent logins = two live refresh tokens for the same user.
    let sa_early = srv.login("superadmin").await;
    let (_reuse_user, first): (String, Value) = dedicated_user(&srv, &sa_early, "ForensicAnalyst").await;
    let second: Value = srv
        .client
        .post(format!("{}/auth/login", srv.base))
        .json(&json!({ "username": _reuse_user, "password": "burn-pass-123" }))
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



/// Fresh user nobody else uses: tests that burn whole-user session state
/// (logout/all, reuse burns, revocations) must not touch seeded accounts
/// that parallel tests hold live tokens for.
async fn dedicated_user(srv: &TestServer, superadmin: &str, role: &str) -> (String, Value) {
    let uname = format!("burn{}{}", role.to_lowercase(), uuid::Uuid::new_v4().to_string()[..8].replace("-", ""));
    let res = srv.client.post(format!("{}/users", srv.base))
        .bearer_auth(superadmin).json(&json!({"username": uname, "password": "burn-pass-123", "role": role}))
        .send().await.unwrap();
    assert_eq!(res.status(), 200, "dedicated user create: {}", res.text().await.unwrap_or_default());
    let tok = srv.client.post(format!("{}/auth/login", srv.base))
        .json(&json!({"username": uname, "password": "burn-pass-123"})).send().await.unwrap();
    assert_eq!(tok.status(), 200);
    (uname, tok.json().await.unwrap())
}

/// Access tokens are allowlisted: self-revocation kills the token mid-TTL
/// while sibling sessions stay valid (logged back in / other token).
#[tokio::test]
async fn access_token_revocation_is_instant() {
    let srv = TestServer::spawn().await;
    let sa = srv.login("superadmin").await;
    let (user_a, tok_a) = dedicated_user(&srv, &sa, "SiteCommander").await;
    // Sibling = second login of the SAME user.
    let tok_b: Value = srv.client.post(format!("{}/auth/login", srv.base))
        .json(&json!({"username": user_a, "password": "burn-pass-123"})).send().await.unwrap().json().await.unwrap();
    // Both live before revocation.
    let pre = srv.client.get(format!("{}/auth/me", srv.base)).bearer_auth(tok_a["access_token"].as_str().unwrap()).send().await.unwrap();
    assert_eq!(pre.status(), 200, "pre-revoke me A: {}", pre.text().await.unwrap_or_default());
    let pre_b = srv.client.get(format!("{}/auth/me", srv.base)).bearer_auth(tok_b["access_token"].as_str().unwrap()).send().await.unwrap();
    assert_eq!(pre_b.status(), 200, "pre-revoke me B: {}", pre_b.text().await.unwrap_or_default());
    // Revoke A; its retries stay idempotent-204.
    assert_eq!(srv.client.post(format!("{}/auth/revoke-access", srv.base)).bearer_auth(tok_a["access_token"].as_str().unwrap()).send().await.unwrap().status(), 204);
    assert_eq!(srv.client.post(format!("{}/auth/revoke-access", srv.base)).bearer_auth(tok_a["access_token"].as_str().unwrap()).send().await.unwrap().status(), 204);
    // A is dead instantly; B is untouched.
    let dead = srv.client.get(format!("{}/auth/me", srv.base)).bearer_auth(tok_a["access_token"].as_str().unwrap()).send().await.unwrap();
    assert_eq!(dead.status(), 401);
    assert_eq!(dead.json::<Value>().await.unwrap()["error"], "token revoked");
    let bres = srv.client.get(format!("{}/auth/me", srv.base)).bearer_auth(tok_b["access_token"].as_str().unwrap()).send().await.unwrap();
    assert_eq!(bres.status(), 200, "me B: {}", bres.text().await.unwrap_or_default());
    // A forged token (valid signature, never allowlisted) is rejected.
    // Sign one via the test binary: reuse login then delete its row.
    let (_, tok_c) = dedicated_user(&srv, &sa, "SiteCommander").await;
    let state = test_state_with_ns(uuid::Uuid::new_v4().to_string()).await;
    // The forged token's own jti, read from its claims (no jwt dep needed).
    let raw_c = tok_c["access_token"].as_str().unwrap();
    use base64::Engine as _;
    let claims: Value = serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw_c.split('.').nth(1).unwrap()).unwrap()).unwrap();
    let jti = claims["jti"].as_str().unwrap().to_owned();
    sqlx::query("DELETE FROM access_tokens WHERE jti = $1::uuid").bind(jti).execute(&state.pool).await.unwrap();
    assert_eq!(srv.client.get(format!("{}/auth/me", srv.base)).bearer_auth(tok_c["access_token"].as_str().unwrap()).send().await.unwrap().status(), 401);
}

/// Logout-all kills sibling access tokens mid-TTL, not just refresh families.
#[tokio::test]
async fn logout_all_kills_sibling_access_tokens() {
    let srv = TestServer::spawn().await;
    let sa = srv.login("superadmin").await;
    let (uname, tok_a) = dedicated_user(&srv, &sa, "SiteCommander").await;
    // Sibling token = SECOND LOGIN of the SAME user.
    let tok_b: Value = srv.client.post(format!("{}/auth/login", srv.base))
        .json(&json!({"username": uname, "password": "burn-pass-123"})).send().await.unwrap().json().await.unwrap();
    assert_eq!(srv.client.post(format!("{}/auth/logout/all", srv.base)).bearer_auth(tok_a["access_token"].as_str().unwrap()).send().await.unwrap().status(), 200);
    assert_eq!(srv.client.get(format!("{}/auth/me", srv.base)).bearer_auth(tok_b["access_token"].as_str().unwrap()).send().await.unwrap().status(), 401);
    assert_eq!(srv.client.get(format!("{}/auth/me", srv.base)).bearer_auth(tok_a["access_token"].as_str().unwrap()).send().await.unwrap().status(), 401);
}

/// The quota is cluster-wide: two replicas sharing one namespace draw from
/// the same budget — exhausting it on A trips B immediately.
#[tokio::test]
async fn rate_limit_quota_is_cluster_wide() {
    let ns = uuid::Uuid::new_v4().to_string();
    let a = TestServer::spawn_with_ns(ns.clone()).await;
    let b = TestServer::spawn_with_ns(ns).await;
    let body = json!({ "username": "nosuch", "password": "x" });
    let mut tripped_on_a = false;
    for _ in 0..25 {
        let res = a.client.post(format!("{}/auth/login", a.base)).json(&body).send().await.unwrap();
        if res.status() == 429 { tripped_on_a = true; break; }
    }
    assert!(tripped_on_a, "quota trips on replica A");
    let res = b.client.post(format!("{}/auth/login", b.base)).json(&body).send().await.unwrap();
    assert_eq!(res.status(), 429, "replica B shares the exhausted budget");
}

#[tokio::test]
async fn totp_enrollment_gates_login() {
    let srv = TestServer::spawn().await;
    let sa = srv.login("superadmin").await;
    // Dedicated user: parallel tests keep logging in seeded users; don't
    // gate those logins mid-test.
    let uname = format!("totpuser{}", uuid::Uuid::new_v4().to_string()[..10].replace("-", ""));
    srv.client.post(format!("{}/users", srv.base))
        .bearer_auth(&sa).json(&json!({"username": uname, "password": "Str0ng-pass!", "role": "VerificationOfficer"}))
        .send().await.unwrap();
    let login = |code: Option<String>| {
        let mut b = json!({"username": uname, "password": "Str0ng-pass!"});
        if let Some(c) = code { b["totp_code"] = json!(c); }
        srv.client.post(format!("{}/auth/login", srv.base)).json(&b).send()
    };
    // Enroll (second login for the setup bearer).
    let first: Value = login(None).await.unwrap().json().await.unwrap();
    let setup: Value = srv.client.post(format!("{}/auth/totp/setup", srv.base))
        .bearer_auth(first["access_token"].as_str().unwrap()).send().await.unwrap().json().await.unwrap();
    let secret = setup["secret"].as_str().unwrap().to_owned();
    let code = totp_code(&secret, chrono::Utc::now().timestamp() / 30);
    let enable: Value = srv.client.post(format!("{}/auth/totp/enable", srv.base))
        .bearer_auth(first["access_token"].as_str().unwrap()).json(&json!({"code": code})).send().await.unwrap().json().await.unwrap();
    assert_eq!(enable["enabled"], true);

    // Login without code → totp_required; with stale/wrong code → invalid.
    let no_code = login(None).await.unwrap();
    assert_eq!(no_code.status(), 401);
    let body: Value = no_code.json().await.unwrap();
    assert_eq!(body["error"], "totp_required");
    let wrong = login(Some("000000".to_owned())).await.unwrap();
    assert_eq!(wrong.status(), 401);

    // With a live-window code → in.
    let good = login(Some(totp_code(&secret, chrono::Utc::now().timestamp() / 30))).await.unwrap();
    assert_eq!(good.status(), 200);
    let tok: Value = good.json().await.unwrap();

    // Disable with a code → back to password-only.
    let disable = srv.client.post(format!("{}/auth/totp/disable", srv.base))
        .bearer_auth(tok["access_token"].as_str().unwrap())
        .json(&json!({"code": totp_code(&secret, chrono::Utc::now().timestamp() / 30)})).send().await.unwrap();
    assert_eq!(disable.status(), 200);
    let plain = login(None).await.unwrap();
    assert_eq!(plain.status(), 200);
}

/// Compute a TOTP at an arbitrary step (mirror of the server recipe).
fn totp_code(secret: &str, step: i64) -> String {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    let decoded = data_encoding::BASE32_NOPAD.decode(secret.to_ascii_uppercase().as_bytes()).unwrap();
    let mut mac = Hmac::<Sha1>::new_from_slice(&decoded).unwrap();
    mac.update(&(step as u64).to_be_bytes());
    let out = mac.finalize().into_bytes();
    let off = (out[19] & 0x0f) as usize;
    let code = (u32::from_be_bytes(out[off..off + 4].try_into().unwrap()) & 0x7fff_ffff) % 1_000_000;
    format!("{code:06}")
}

#[tokio::test]
async fn session_revoke_kills_other_session_not_current() {
    let srv = TestServer::spawn().await;
    // Two independent logins = two sessions (dedicated user — parallel
    // tests must not burn these tokens mid-test).
    let sa = srv.login("superadmin").await;
    let (uname, a) = dedicated_user(&srv, &sa, "SiteCommander").await;
    let b: Value = srv.client.post(format!("{}/auth/login", srv.base))
        .json(&json!({"username": uname, "password": "burn-pass-123"})).send().await.unwrap().json().await.unwrap();

    // Shared DB: other tests leave live commander sessions behind. Identify
    // OUR two by each token's own current-session marker.
    let list = |tok: &str, base: String| {
        let tok = tok.to_owned();
        async move {
            let v: Value = reqwest::Client::new().get(format!("{base}/auth/sessions"))
                .bearer_auth(tok).send().await.unwrap().json().await.unwrap();
            v
        }
    };
    let a_list = list(a["access_token"].as_str().unwrap(), srv.base.clone()).await;
    let b_list = list(b["access_token"].as_str().unwrap(), srv.base.clone()).await;
    let a_sid = a_list["sessions"].as_array().unwrap().iter()
        .find(|s| s["current"] == true).unwrap()["session_id"].as_str().unwrap().to_owned();
    let b_sid = b_list["sessions"].as_array().unwrap().iter()
        .find(|s| s["current"] == true).unwrap()["session_id"].as_str().unwrap().to_owned();
    assert_ne!(a_sid, b_sid);

    // Revoking self refused; revoking the other one works.
    let self_res = srv.client.post(format!("{}/auth/sessions/{}/revoke", srv.base, a_sid))
        .bearer_auth(a["access_token"].as_str().unwrap()).send().await.unwrap();
    assert_eq!(self_res.status(), 400);
    let kill = srv.client.post(format!("{}/auth/sessions/{}/revoke", srv.base, b_sid))
        .bearer_auth(a["access_token"].as_str().unwrap()).send().await.unwrap();
    assert_eq!(kill.status(), 200);

    // Session B's access token dies instantly (allowlist row revoked).
    let b_check = srv.client.get(format!("{}/auth/me", srv.base))
        .bearer_auth(b["access_token"].as_str().unwrap()).send().await.unwrap();
    assert_eq!(b_check.status(), 401, "revoked session access token dies immediately");
    // And B's refresh is dead too.
    let b_refresh = srv.client.post(format!("{}/auth/refresh", srv.base))
        .json(&json!({"refresh_token": b["refresh_token"].as_str().unwrap()})).send().await.unwrap();
    assert_eq!(b_refresh.status(), 401);
}
