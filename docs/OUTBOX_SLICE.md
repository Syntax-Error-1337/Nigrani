# Kiosk Offline Outbox — Scope Note (t115, sprint s39)

## Gap
Kiosk `record()` is fire-and-forget: network error or 5xx/429 → notice
line, crossing LOST. Protest sites have flaky connectivity and rush
bursts; the operator's only recourse is re-typing the flow from scratch
(re-verify card, re-pick direction, re-stage photo). Lost crossings are
silent crowd-count holes — the heatmap undercounts with no trace.

## Design
- Outbox in `session.ts`-adjacent module (`outbox.ts`): `localStorage`
  persisted queue `sg-outbox` of `{id, siteId, gateId, direction, method,
  press_card, snapshot_key, queued_at, attempts}`. Enqueue ONLY on
  network-level failure (fetch throws) or 5xx/429 — NEVER on 4xx (those
  are verdicts: recalls would duplicate or fight validation; the denial
  copy already covers them).
- Flush: on mount + after every successful record + on `online` event +
  manual RETRY button. FIFO, stop-on-first-failure with backoff
  (attempts counter, 2s*attempts cap 30s via setTimeout chain — no
  external deps). Successful flush removes + `log.refetch()`.
- UI: pending count pill in the kiosk header (`N PENDING`) + RETRY
  button; per-item direction/method/time in a collapsible <details>.
  Snapshot keys ride along (already-uploaded S3 keys — uploads happen
  BEFORE record, so queued items reference stored objects; orphan
  collector (s25) covers the never-flushed case — documented interplay).
- Card payloads in localStorage: same sensitivity as the session JWT
  already stored there — no new posture (note it in code comment).
- Dedupe guard: each item carries client `id`; server has no dedupe key
  (out of scope) — flush stops at first failure so ordering is stable
  and double-submit requires a crash between POST-success and
  response-receipt (accepted, documented; crossings are idempotent-ish
  by human review).

## Out
Server-side idempotency keys; background-sync API; conflict UI for
archived-gate-at-flush (410s drop with notice — actually INCLUDE: 410 on
flush drops the item + surfaces "gate retired, N dropped". Cheap,
do it).

## Acceptance
- Airplane-mode record → queued + count; reconnect/RETRY → flushed +
  log shows it; 400s never queue; 410-at-flush drops with notice.
- tsc + oxlint clean; live UI proof with real offline toggle (request
  blocking via CDP or API stop).
