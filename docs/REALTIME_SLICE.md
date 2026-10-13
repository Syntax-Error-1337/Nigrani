# Realtime Events — Scope Note (t31, sprint s11)

## Gap
Spec diagram promises "Events (WebSockets)" to the dashboard; today every
panel polls via manual `refetch()`. A commander watching two gates sees
stale crossings until they act.

## Design
- Backend: `tokio::sync::broadcast` hub (capacity 256) on `AppState`.
  Publishers: `record_event` (gate crossings), `decide_kyc` (approvals/
  rejections). Event JSON: `{kind, at, site_id?, gate_id?, payload}`.
- `GET /events` upgrades to WebSocket (axum `WebSocketUpgrade`); auth via
  `?token=<jwt>` query (WS clients can't set headers reliably) verified
  with the same JWT path as `AuthUser`. Permission: any authenticated
  role; payloads carry no PII beyond names already visible to the role
  (document numbers never published).
- Frontend: single shared `useEventStream` hook (reconnect with backoff,
  heartbeat ignore) invalidating tanstack-query keys:
  `gate-log` on crossing, `kyc` on decision, `sites`/`gates` on topology
  changes (site/gate created). Manual refetch buttons stay as fallback.

## Out
Per-site subscription filtering (one global stream; client filters),
RabbitMQ bridging (recorded — single-instance broadcast suffices),
native mobile push.

## Acceptance
- Two curl WS clients: event POSTed via API appears on both sockets <1s.
- Browser: log a crossing in one tab, watch it appear in another tab's
  kiosk log without clicking.
- Suite green (broadcast unit test: publish → two receivers); clippy clean.
