# QR Press Cards — Scope Note (t40, sprint s14)

## Gap
Phase 2 shipped the signed press-card *payload* but deferred image
rendering ("paste into any QR generator"). Gates scan QR images, not JSON
blobs — the generator service the blueprint names is still missing.

## Design
- Backend: `GET /kyc/applications/:id/press-card.png` (needs `kyc:review`,
  same gate as the JSON endpoint) → PNG QR encoding the canonical signed
  payload JSON. Crates: `qrcode` (render) + `image` (PNG encode). Error
  correction M, 512px, quiet zone included.
- The PNG encodes byte-for-byte the same JSON `/press-card` returns, so
  the existing HMAC + `/kyc/verify` path verifies scans unchanged.
- Frontend ReviewDesk: "press card" button shows the QR `<img>` (fetch as
  blob URL) replacing the paste-this-payload panel; kiosk keeps accepting
  pasted JSON (manual fallback for damaged prints).
- Kiosk (later, recorded out): camera scan of the QR — needs device
  hardware absent here.

## Out
Camera-side QR scanning UI, print layout/PDF cards, wallet passes.

## Acceptance
- PNG endpoint 200 with `image/png`; rxing (independent ZXing port)
  decodes it and recovers the signed fields; both payloads verify.
- Suite green; clippy clean.
