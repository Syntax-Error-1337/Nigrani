import { useState } from 'react'
import { apiFetch } from './session'
import { useGateLog, type PressCard } from './api'

function apiError(body: unknown, fallback: string): string {
  if (body !== null && typeof body === 'object' && 'error' in body) {
    const err: unknown = body.error
    if (typeof err === 'string' && err.length > 0) return err
  }
  return fallback
}

/// Operator copy per denial class: forgery confronts, revocation and
/// pending redirect. Server `reason` values are stable API (s24).
function denialCopy(reason: unknown): string {
  if (reason === 'revoked') return 'Card revoked — redirect holder to the press desk'
  if (reason === 'not_approved') return 'Application not approved — redirect to accreditation'
  return 'Card signature invalid — deny entry'
}

/// Record-time refusal mirrors the same copy (server messages are literal
/// constants quoted in backend tests).
function recordDenialCopy(serverMessage: string): string | null {
  if (serverMessage.includes('press card revoked')) return denialCopy('revoked')
  if (serverMessage.includes('not approved')) return denialCopy('not_approved')
  if (serverMessage.includes('failed verification')) return denialCopy('bad_signature')
  return null
}

function isPressCard(body: unknown): body is PressCard {
  if (body === null || typeof body !== 'object') return false
  return (
    'application_id' in body &&
    'full_name' in body &&
    'signature' in body &&
    typeof body.application_id === 'string' &&
    typeof body.full_name === 'string'
  )
}

export default function Kiosk({
  siteId,
  gateId,
}: {
  siteId: string | null
  gateId: string | null
}) {
  const [payload, setPayload] = useState('')
  const [card, setCard] = useState<PressCard | null>(null)
  const [direction, setDirection] = useState<'entry' | 'exit'>('entry')
  const [snapshotKey, setSnapshotKey] = useState('')
  const [shareUrl, setShareUrl] = useState('')
  const [preview, setPreview] = useState<{ key: string; url: string } | null>(null)
  const [uploading, setUploading] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const [ok, setOk] = useState<string | null>(null)
  const log = useGateLog(siteId, gateId)

  async function verify() {
    setNotice(null)
    setOk(null)
    let parsed: unknown
    try {
      parsed = JSON.parse(payload)
    } catch {
      setNotice('Card payload is not valid JSON')
      return
    }
    const res = await apiFetch('/kyc/verify', { method: 'POST', body: JSON.stringify(parsed) })
    const body: unknown = await res.json().catch(() => ({}))
    if (!res.ok) {
      setNotice(apiError(body, 'Verification failed'))
      return
    }
    if (
      body !== null &&
      typeof body === 'object' &&
      'valid' in body &&
      body.valid === true &&
      isPressCard(parsed)
    ) {
      setCard(parsed)
      setOk(`Verified — ${parsed.full_name}`)
    } else {
      setCard(null)
      const reason =
        body !== null && typeof body === 'object' && 'reason' in body ? body.reason : null
      setNotice(denialCopy(reason))
    }
  }

  async function uploadSnapshot(file: File) {
    setUploading(true)
    setNotice(null)
    try {
      const buf = await file.arrayBuffer()
      const res = await apiFetch('/snapshots', {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: buf,
      })
      const body: unknown = await res.json().catch(() => ({}))
      if (!res.ok) {
        setNotice(apiError(body, 'Snapshot upload failed'))
        return
      }
      if (body !== null && typeof body === 'object' && 'key' in body && typeof body.key === 'string') {
        setSnapshotKey(body.key)
        const share = await apiFetch(`/snapshots/${body.key}/share`)
        if (share.ok) {
          const shareBody: unknown = await share.json().catch(() => ({}))
          if (shareBody !== null && typeof shareBody === 'object' && 'url' in shareBody && typeof shareBody.url === 'string') {
            setShareUrl(shareBody.url)
          }
        }
      }
    } finally {
      setUploading(false)
    }
  }

  async function openPreview(key: string) {
    setNotice(null)
    const res = await apiFetch(`/snapshots/${key}/share`)
    if (!res.ok) {
      setNotice('Capture unavailable')
      return
    }
    const body: unknown = await res.json().catch(() => ({}))
    if (body !== null && typeof body === 'object' && 'url' in body && typeof body.url === 'string') {
      setPreview({ key, url: body.url })
    }
  }

  async function record(method: 'press_card' | 'manual') {
    setNotice(null)
    setOk(null)
    if (siteId === null || gateId === null) {
      setNotice('Select a site and gate first')
      return
    }
    if (method === 'press_card' && !card) {
      setNotice('Verify a press card first')
      return
    }
    const res = await apiFetch(`/sites/${siteId}/gates/${gateId}/events`, {
      method: 'POST',
      body: JSON.stringify({
        direction,
        method,
        press_card: method === 'press_card' ? card : null,
        snapshot_key: snapshotKey || null,
      }),
    })
    const body: unknown = await res.json().catch(() => ({}))
    if (!res.ok) {
      const raw =
        body !== null && typeof body === 'object' && 'error' in body && typeof body.error === 'string'
          ? body.error
          : ''
      setNotice(recordDenialCopy(raw) ?? apiError(body, 'Could not record entry'))
      return
    }
    setOk(method === 'manual' ? 'Manual entry logged' : `Entry logged — ${card?.full_name}`)
    setCard(null)
    setPayload('')
    setSnapshotKey('')
    setShareUrl('')
    log.refetch()
  }

  return (
    <section className="mt-8">
      <h2 className="font-display text-2xl uppercase">Gate kiosk</h2>
      {!gateId ? <p className="mt-2">Select a gate above to open the screening post.</p> : null}
      {notice ? (
        <p role="alert" className="mt-3 border border-deny bg-red-50 px-3 py-2 text-sm text-deny">
          {notice}
        </p>
      ) : null}
      {ok ? (
        <p className="mt-3 border border-ok bg-green-50 px-3 py-2 text-sm text-ok">{ok}</p>
      ) : null}
      <div className="mt-3 grid gap-4 md:grid-cols-2">
        <div className="border-2 border-ink bg-white p-4">
          <label className="flex flex-col gap-1 text-sm">
            Press-card payload (scanned QR JSON)
            <textarea
              className="border border-ink px-3 py-2 font-ledger text-xs"
              rows={4}
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              placeholder='{"application_id": …}'
            />
          </label>
          <div className="mt-2 flex gap-2">
            <button onClick={verify} className="bg-ink px-4 py-2 text-sm uppercase text-paper">
              Verify card
            </button>
            <label className="flex flex-col gap-1 text-sm">
              Direction
              <select
                className="border border-ink px-3 py-2"
                value={direction}
                onChange={(e) => setDirection(e.target.value as 'entry' | 'exit')}
              >
                <option value="entry">Entry</option>
                <option value="exit">Exit</option>
              </select>
            </label>
          </div>
          <label className="mt-3 flex flex-col gap-1 text-sm">
            Snapshot (JPEG ≤ 5MB)
            <input
              type="file"
              accept="image/jpeg"
              disabled={uploading}
              onChange={(e) => {
                const f = e.target.files?.[0]
                if (f) uploadSnapshot(f)
              }}
            />
          </label>
          {snapshotKey ? (
            <p className="mt-1 font-ledger text-xs">
              staged: {snapshotKey}
              {shareUrl ? (
                <>
                  {' — '}
                  <a className="underline" href={shareUrl} target="_blank" rel="noreferrer">
                    open capture
                  </a>
                </>
              ) : null}
            </p>
          ) : null}
          <div className="mt-3 flex gap-2">
            <button
              onClick={() => record('press_card')}
              className="bg-ok px-4 py-2 text-sm uppercase text-white"
            >
              Log card entry
            </button>
            <button
              onClick={() => record('manual')}
              className="border border-ink px-4 py-2 text-sm uppercase"
            >
              Log manual entry
            </button>
          </div>
        </div>
        <div className="border-2 border-ink bg-white p-4">
          <h3 className="font-display text-lg uppercase">Recent crossings</h3>
          {log.isLoading ? <p className="mt-2 text-sm">Loading log…</p> : null}
          {(log.data ?? []).length === 0 && !log.isLoading ? (
            <p className="mt-2 text-sm">No crossings recorded at this gate yet.</p>
          ) : null}
          <ol className="mt-2 divide-y divide-neutral-200">
            {(log.data ?? []).map((e) => (
              <li key={e.id} className="flex items-center gap-2 py-1 font-ledger text-xs">
                <span className="uppercase">{e.direction}</span>
                <span>{e.method === 'press_card' ? 'card' : 'manual'}</span>
                {e.holder_name ? (
                  <span className="font-display uppercase" title={e.holder_org ?? ''}>{e.holder_name}</span>
                ) : null}
                {e.snapshot_key ? (
                  <button
                    onClick={() => openPreview(e.snapshot_key)}
                    className="border border-ink px-1 uppercase"
                  >
                    Photo
                  </button>
                ) : null}
                <span className="ml-auto">{new Date(e.recorded_at).toLocaleTimeString()}</span>
              </li>
            ))}
          </ol>
          {preview ? (
            <div className="mt-2 border-2 border-signal bg-white p-2">
              <img src={preview.url} alt={`Gate capture ${preview.key}`} className="max-h-64 w-auto" />
              <button onClick={() => setPreview(null)} className="mt-1 border border-ink px-2 py-1 uppercase">
                Close
              </button>
            </div>
          ) : null}
        </div>
      </div>
    </section>
  )
}
