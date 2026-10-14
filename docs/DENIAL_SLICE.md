# Kiosk Denial Reasons — Scope Note (t112, sprint s38)

## Gap
The kiosk collapses every `valid:false` into "Card signature invalid —
deny entry". Since s24 the API returns `reason` (ok/bad_signature/
revoked/not_approved) but no UI reads it. Operational difference matters:
- forged (`bad_signature`): potential impersonation — detain, escalate.
- `revoked`: credential pulled post-approval — redirect holder to the
  press desk, no confrontation needed.
- `not_approved`: pending/rejected application walking up early —
  redirect to accreditation.
One denial line for all three trains the wrong response.

## Design
- `verify()`: branch on `body.reason` when `valid` is false:
  - `revoked` → "Card revoked — redirect holder to the press desk"
  - `not_approved` → "Application not approved — redirect to accreditation"
  - else (bad_signature/unparseable) → keep "Card signature invalid —
    deny entry".
- Same mapping for the record-time 403 path (`record()` POSTs the event
  and the server refuses revoked cards): match the refusal message
  (`press card revoked` / `not approved` substrings) to the same copy.
  String-match on the stable server messages (they're literal constants
  in routes_gate — quoted in tests, safe to mirror).
- No backend change. No new strings beyond the three operator lines.

## Out
Audible/lamp signals per denial class; escalation ticket creation;
localizing copy per site language.

## Acceptance
- tsc + oxlint clean.
- Live UI proof as gate: revoked card → desk-redirect copy; tampered
  card → forgery copy; pending-app card → accreditation copy.
