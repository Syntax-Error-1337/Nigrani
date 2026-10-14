# Audit Detail Inspector — Scope Note (t124, sprint s42)

## Gap
Trail rows render `seq/action/entity/time` but never `detail` — the field
carrying the actual story (usernames, strikes, purge counts, gate ids,
decision strings). An operator verifying "who locked whom" or "what did
the purge take" must curl. The data is fetched (`detail: unknown` in the
row type) and dropped on the floor.

## Design
- Per-row `<details>` expander showing `detail` as sorted `key: value`
  lines (NOT raw JSON.stringify — readable ledger typography matching
  the row style). Empty `{}` renders `—` (no expander chrome for empty).
- Safe render: values via String(value) for string/number/bool/null;
  nested objects/arrays via compact JSON.stringify (one level — details
  are flat operational facts by convention; no recursive tree widget).
- No backend change. No new deps. Client-only render of already-fetched
  data (zero new requests, zero permission surface change).

## Out
Detail search/filter; diff view between rows; copy-JSON button.

## Acceptance
- tsc + oxlint clean.
- Live UI proof as superadmin: load trail, expand a row, detail keys
  visible in DOM.
