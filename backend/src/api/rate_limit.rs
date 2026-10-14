use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Fixed-window limiter. Single-instance only: a second replica keeps its own
/// counters (documented; shared quota needs Redis — out of scope).
/// One instance lives on `AppState`, so tests get isolated quotas.
#[derive(Debug, Clone)]
pub struct Limiter {
    inner: Arc<Mutex<HashMap<IpAddr, Window>>>,
    max_hits: u32,
    window: Duration,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    count: u32,
    started: Instant,
}

/// Route-attached rule: which quota guards this route. Inserted as an
/// `Extension` alongside the `Limiter` it points at.
#[derive(Debug, Clone)]
pub struct LimitRule {
    pub limiter: Limiter,
    pub endpoint: &'static str,
}

impl Limiter {
    pub fn new(max_hits: u32, window: Duration) -> Self {
        Self { inner: Arc::new(Mutex::new(HashMap::new())), max_hits, window }
    }

    pub fn kyc() -> Self {
        Self::new(10, Duration::from_secs(60))
    }

    pub fn auth_login() -> Self {
        Self::new(20, Duration::from_secs(60))
    }

    pub fn auth_refresh() -> Self {
        Self::new(30, Duration::from_secs(60))
    }

    /// 5MB JPEG ingest: generous for kiosk staging (one photo per human-rate
    /// crossing), tight enough to blunt credential-compromise floods.
    pub fn snapshot_upload() -> Self {
        Self::new(30, Duration::from_secs(60))
    }

    fn allow(&self, ip: IpAddr) -> bool {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Opportunistic prune keeps the map bounded without a sweeper task.
        if map.len() > 10_000 {
            let now = Instant::now();
            map.retain(|_, w| now.duration_since(w.started) < self.window);
        }
        let now = Instant::now();
        let entry = map
            .entry(ip)
            .and_modify(|w| {
                if now.duration_since(w.started) >= self.window {
                    *w = Window { count: 0, started: now };
                }
            })
            .or_insert(Window { count: 0, started: now });
        entry.count += 1;
        entry.count <= self.max_hits
    }
}

/// Per-IP fixed-window gate. Reads the route's [`LimitRule`] extension;
/// routes without one pass through untouched.
pub async fn limit_by_rule(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let rule = request.extensions().get::<LimitRule>().cloned();
    let allowed = rule.as_ref().is_none_or(|r| r.limiter.allow(addr.ip()));
    if allowed {
        next.run(request).await
    } else {
        let endpoint = rule.map(|r| r.endpoint).unwrap_or("unknown");
        tracing::warn!(ip = %addr.ip(), endpoint, "rate limited");
        (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded; try again shortly").into_response()
    }
}

/// Back-compat alias: the KYC submit route keeps its own name.
pub async fn kyc_limiter(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    limit_by_rule(ConnectInfo(addr), request, next).await
}
