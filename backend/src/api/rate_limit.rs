use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::state::AppState;

/// Route-attached rule: which quota guards this route. Inserted as an
/// `Extension` alongside the route group it guards.
#[derive(Debug, Clone)]
pub struct LimitRule {
    pub endpoint: &'static str,
    pub max_hits: u32,
    pub window_secs: i64,
}

impl LimitRule {
    const fn new(max_hits: u32, window_secs: i64, endpoint: &'static str) -> Self {
        Self { endpoint, max_hits, window_secs }
    }

    pub fn kyc() -> Self {
        Self::new(10, 60, "kyc_submit")
    }

    pub fn auth_login() -> Self {
        Self::new(20, 60, "auth_login")
    }

    pub fn auth_refresh() -> Self {
        Self::new(30, 60, "auth_refresh")
    }

    /// 5MB JPEG ingest: generous for kiosk staging (one photo per human-rate
    /// crossing), tight enough to blunt credential-compromise floods.
    pub fn snapshot_upload() -> Self {
        Self::new(30, 60, "snapshot_upload")
    }
}

/// Cluster-wide per-IP fixed-window gate. Counters live in the shared
/// `rate_counters` table (see migration 0019), so every replica draws from
/// the same budget instead of doubling each quota. The limiter key is
/// namespaced per instance: production replicas share the empty namespace;
/// each test server mints its own so suites stay isolated.
pub async fn limit_by_rule(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let Some(rule) = request.extensions().get::<LimitRule>() else {
        return next.run(request).await;
    };
    let key = format!("{}/{}", rule.endpoint, state.rate_ns);
    let allowed = allow(&state.pool, &key, &addr.ip().to_string(), rule.max_hits, rule.window_secs).await;
    if allowed {
        next.run(request).await
    } else {
        tracing::warn!(ip = %addr.ip(), endpoint = rule.endpoint, "rate limited");
        (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded; try again shortly").into_response()
    }
}

/// One UPSERT per request; the DB computes the window boundary so all
/// replicas agree without clock coupling beyond NTP.
/// DB hiccup => fail OPEN with a warn: a quota gate must not take auth
/// down with it (worst case, the flood window is wider).
async fn allow(
    pool: &sqlx::PgPool,
    limiter: &str,
    ip: &str,
    max_hits: u32,
    window_secs: i64,
) -> bool {
    let row: Option<i64> = sqlx::query_scalar(
        "INSERT INTO rate_counters (limiter, ip, window_start, count)
         VALUES ($1, $2, to_timestamp(floor(extract(epoch from now()) / $3) * $3), 1)
         ON CONFLICT (limiter, ip, window_start)
         DO UPDATE SET count = rate_counters.count + 1
         RETURNING count::bigint",
    )
    .bind(limiter)
    .bind(ip)
    .bind(window_secs)
    .fetch_one(pool)
    .await
    .ok();
    let Some(count) = row else {
        tracing::warn!(limiter, "rate counter unavailable; failing open");
        return true;
    };
    // First hit in a window: opportunistically prune stale rows so the
    // table stays bounded without a sweeper task.
    if count == 1 {
        let _ = sqlx::query("DELETE FROM rate_counters WHERE window_start < now() - interval '10 minutes'")
            .execute(pool)
            .await;
    }
    count <= i64::from(max_hits)
}
