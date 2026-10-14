# Required Rejection Notes — Scope Note (t130, sprint s44)

## Gap
`decide` accepts `{"decision": "rejected"}` with NO note: the journalist's
row flips to REJECTED with an empty `decision_note`, zero recourse info
(blurry scan? wrong doc? re-apply?). The desk input even says "optional",
training reviewers to skip it. Approvals need no justification (the card
IS the outcome), but a rejection without reason is a dead end for the
applicant and unactionable for re-application review (`prior_decisions`
shows a bare prior reject).

## Design
- Backend: `rejected` with blank/missing note → 400 "rejection requires
  a note" (trimmed, min 3 chars — kills whitespace-only notes).
  `approved` unchanged (note stays optional, stored as-is).
- Desk: input placeholder becomes decision-aware — "Reason (required
  for rejection)" — plus client-side guard in `decide()` for the reject
  path ("Add a reason first") so reviewers learn before the 400.
- Existing test at slice.rs:162 decides rejected WITHOUT a note — must
  be updated to carry one (it asserts 200-path behavior elsewhere? check:
  it only asserts status reachability — update to include note).
- Audit: none new (decide already audits with decision string).

## Out
Applicant-visible status portal (no PII-safe lookup exists); templated
rejection reasons dropdown; note editing post-decision (immutability
doctrine stands).

## Acceptance
- Reject without note → 400; whitespace note → 400; reject with note →
  200 and note round-trips; approve without note → 200.
- Suite green (incl. updated s2-era test); clippy/tsc clean; live curl
  + UI proof.
