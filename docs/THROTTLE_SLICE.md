# Snapshot Upload Throttling — Scope Note (t100, sprint s34)

## Gap
`POST /snapshots` accepts 5MB JPEGs with NO rate limit. Every other
expensive/anonymous surface is throttled (kyc_submit 10/min, auth_login
20/min, auth_refresh 30/min) — but the highest-bandwidth endpoint of all
is open. A compromised gate-operator credential, a kiosk bug in a retry
loop, or a malicious insider fills S3 (and the orphan collector's plate)
at line rate. Upload requires auth (`entries:write`), so this is insider/
agent-bug throttling, not anonymous-abuse throttling — the quota can be
generous.

## Design
- New `Limiter::snapshot_upload()` — 30/min per IP (matches the 30/min
  refresh quota family; a kiosk staging photos for manual crossings peaks
  far below this — one photo per crossing, crossings are human-rate).
- Wire via the existing `limited()` helper + `LimitRule { endpoint:
  "snapshot_upload" }` in mod.rs (same 3-line pattern as kyc/auth).
- `AppState` gains `snapshot_limiter`; `test_state()` gains the same
  (isolated quotas per test server — existing pattern).
- 429 body reuses the shared "rate limit exceeded; try again shortly"
  (no new strings; kiosk surfaces it via the existing upload-failure
  notice path — verify no kiosk change needed).
- Audit: none (throttled requests never reach the handler, consistent
  with kyc/auth limits).

## Out
Per-user (vs per-IP) quotas; S3 byte-quotas per site; upload deduplication
by content hash.

## Acceptance
- 31 rapid uploads → 429 observed (mirrors kyc_submit test shape);
  window recovery implied by fixed-window design (no sleep-the-suite).
- Suite green; clippy clean; live curl proof of 429.
