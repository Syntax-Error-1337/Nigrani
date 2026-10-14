# Live Incident Bench — Scope Note (t61, sprint s21)

## Gap
s19 publishes `HubEvent::Incident` on all four case mutations, but the
frontend drops them: `isHubEvent` in `events.ts` accepts only
crossing/kyc_decided/topology, so incident traffic is parsed and
discarded. Two analysts on the same case: B files a note, A stares at a
stale list until they click Refresh. The realtime slice is half-landed.

Second half: `ForensicBench` holds incidents in local `useState` —
react-query invalidation keys can't reach it. The event hook and the
bench need a bridge that doesn't rewrite the bench's data layer.

## Design
- `events.ts`: accept `kind: 'incident'` with `{ site_id?, incident_id?,
  action? }`. On incident events, notify a tiny subscriber set (module-
  level `Set<(siteId: string | null) => void>`, subscribe/unsubscribe
  helpers) instead of query invalidation — the bench isn't on react-query.
  Keep the existing invalidation branches untouched.
- `ForensicBench`: `useEffect` subscribes on mount with current `siteId`
  (re-subscribe when it changes); on an event whose `site_id` matches (or
  is absent — older payloads always carry it, be liberal), call
  `loadIncidents()` and drop cached links for the touched `incident_id`
  (status/assign change row rendering; links list refreshes on next open
  — actually just reload links too if that incident's links are open).
- No new deps, no query-key migration, no change to the bench's manual
  Refresh button (stays as the lag/drop fallback, consistent with the
  stream-is-a-hint contract).

## Out
Migrating the bench to react-query; per-incident row patching instead of
full reload; toast-on-event ("case updated by …" — no actor in payload).

## Acceptance
- tsc + oxlint clean.
- Live two-session proof: tab A loads incidents; curl (or tab B)
  transitions a case; tab A shows the new status WITHOUT clicking
  Refresh (DOM text assertion via browser tool).
