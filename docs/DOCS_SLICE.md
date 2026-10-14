# Operator Docs Refresh — Scope Note (t79, sprint s27)

## Gap
README documents ~s6-era surface: missing lockout, unlock, archive/restore,
revoke-card, incident lifecycle (status/assign/links), duplicate guard
semantics (409), snapshot collect console, orphan block, audit scoping +
verify, retention policies/purge/export, demo reset, logout-all, request-id
errors, event stream incident kinds. A new operator following README walks
into 404s of understanding (endpoints exist but are undiscoverable) and
stale claims (test count "10", QR "use any generator" — shipped in s14).

## Design
- Rewrite README API + console sections from the ROUTER (mod.rs is the
  source of truth — 40+ routes), not memory. Structure: Quick start
  (keep) → Auth & accounts (login/lockout/unlock/provision/password) →
  Topology (sites/gates/archive) → Press KYC (submit/review/duplicates/
  cards/revoke) → Gate ops (events/log/snapshots) → Forensics (embeddings/
  incidents/links/heatmap) → Realtime stream → Audit → Retention &
  snapshots-collect → Demo reset → Errors (request-id envelope, status
  code guide incl. 409/410/429) → Console tour per role → Tests (real
  count) → Layout → Out of scope (refresh: strike shipped items).
- Verify pass (t81): every METHOD+PATH grepped against mod.rs; every
  status code quoted from errors.rs/handlers; console panel names from
  frontend source. Suite re-run to prove untouched-green.

## Out
Man pages, OpenAPI spec generation, translated docs, video walkthroughs.

## Acceptance
- Zero stale claims (test count, QR note, missing endpoints fixed).
- t81 checklist: route table diffed vs router; console names diffed vs
  source; clippy/tests green (docs-only, but prove it).
