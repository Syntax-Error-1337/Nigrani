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

impl Limiter {
    pub fn new(max_hits: u32, window: Duration) -> Self {
        Self { inner: Arc::new(Mutex::new(HashMap::new())), max_hits, window }
    }

    pub fn kyc() -> Self {
        Self::new(10, Duration::from_secs(60))
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

/// Public KYC submit gate: 10 requests/minute per client IP.
/// Reads the per-`AppState` limiter from the request extension.
pub async fn kyc_limiter(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let allowed = request
        .extensions()
        .get::<Limiter>()
        .is_none_or(|limiter| limiter.allow(addr.ip()));
    if allowed {
        next.run(request).await
    } else {
        tracing::warn!(ip = %addr.ip(), "kyc submit rate limited");
        (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded; try again shortly").into_response()
    }
}
