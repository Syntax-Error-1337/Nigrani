//! Prometheus-style metrics (s-I5): hand-rolled counters + DB gauges in
//! the text exposition format, no new dependency. `/metrics` is unauthenticated
//! (operational facts only — no PII, no business rows) and scraped by the
//! cluster's Prometheus; see k8s/nigrani.yaml annotations.
use std::sync::atomic::{AtomicU64, Ordering};

/// Requests served, by response status class (1xx-5xx buckets).
static REQ_2XX: AtomicU64 = AtomicU64::new(0);
static REQ_4XX: AtomicU64 = AtomicU64::new(0);
static REQ_5XX: AtomicU64 = AtomicU64::new(0);

pub fn count_response(status: u16) {
    match status {
        200..=299 => REQ_2XX.fetch_add(1, Ordering::Relaxed),
        400..=499 => REQ_4XX.fetch_add(1, Ordering::Relaxed),
        500..=599 => REQ_5XX.fetch_add(1, Ordering::Relaxed),
        _ => 0,
    };
}

/// Live business-row gauges read at scrape time.
pub async fn scrape(state: &super::state::AppState) -> String {
    let (users,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&state.pool).await.unwrap_or((0,));
    let (sites,): (i64,) = sqlx::query_as("SELECT count(*) FROM sites")
        .fetch_one(&state.pool).await.unwrap_or((0,));
    let (entries24,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM entry_logs WHERE recorded_at > now() - interval '24 hours'")
        .fetch_one(&state.pool).await.unwrap_or((0,));
    let (open_cases,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM incidents WHERE status IN ('open','investigating')")
        .fetch_one(&state.pool).await.unwrap_or((0,));
    format!(
        "# HELP nigrani_requests_total HTTP requests served, by status class.\n\
         # TYPE nigrani_requests_total counter\n\
         nigrani_requests_total{{class=\"2xx\"}} {}\n\
         nigrani_requests_total{{class=\"4xx\"}} {}\n\
         nigrani_requests_total{{class=\"5xx\"}} {}\n\
         # HELP nigrani_rows_total Live business-row gauges.\n\
         # TYPE nigrani_rows_total gauge\n\
         nigrani_rows_total{{entity=\"users\"}} {}\n\
         nigrani_rows_total{{entity=\"sites\"}} {}\n\
         nigrani_rows_total{{entity=\"entries_24h\"}} {}\n\
         nigrani_rows_total{{entity=\"open_incidents\"}} {}\n",
        REQ_2XX.load(Ordering::Relaxed),
        REQ_4XX.load(Ordering::Relaxed),
        REQ_5XX.load(Ordering::Relaxed),
        users, sites, entries24, open_cases,
    )
}

/// Count every response's status class (registered outermost).
pub async fn count_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let res = next.run(req).await;
    count_response(res.status().as_u16());
    res
}
