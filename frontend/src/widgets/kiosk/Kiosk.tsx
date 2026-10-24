import { useEffect, useRef, useState } from 'react'
import { apiFetch } from '@/shared/api'
import { useGateLog } from '@/entities/gate-log'
import type { PressCard } from '@/entities/kyc'
import { enqueueCrossing, flushOutbox, retryDelayMs, useOutbox } from '@/shared/lib/outbox'

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
  if (reason === 'expired') return 'Card expired — redirect holder to the press desk for reissue'
  if (reason === 'superseded') return 'Card superseded by a newer print — deny entry'
  return 'Card signature invalid — deny entry'
}

/// Record-time refusal mirrors the same copy (server messages are literal
/// constants quoted in backend tests).
function recordDenialCopy(serverMessage: string): string | null {
  if (serverMessage.includes('at capacity')) return 'Site at capacity — hold the queue, admit on exit'
  if (serverMessage.includes('press card revoked')) return denialCopy('revoked')
  if (serverMessage.includes('not approved')) return denialCopy('not_approved')
  if (serverMessage.includes('press card expired')) return denialCopy('expired')
  if (serverMessage.includes('press card superseded')) return denialCopy('superseded')
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
  const [offline, setOffline] = useState(!navigator.onLine)
  const log = useGateLog(siteId, gateId)
  const pending = useOutbox()
  const [flushing, setFlushing] = useState(false)
  const crl = useRef<CachedCrl | null>(null)

  // --- Offline support ---
  // Deny list cached from the CRL (refreshed every 5 min while online);
  // offline scans deny known-dead cards and otherwise bounce to the
  // audited manual override (browser can't recompute the server HMAC).
  interface CachedCrl {
    fetched_at: string
    revoked: { application_id: string }[]
    expired: { application_id: string }[]
    superseded: { application_id: string }[]
  }
  const CRL_KEY = 'sg-crl'

  function loadCachedCrl() {
    try {
      const raw = localStorage.getItem(CRL_KEY)
      if (raw) crl.current = JSON.parse(raw) as CachedCrl
    } catch {
      crl.current = null
    }
  }

  async function refreshCrl() {
    if (!navigator.onLine) return
    try {
      const res = await apiFetch('/kyc/crl')
      if (!res.ok) return
      const body = (await res.json()) as Omit<CachedCrl, 'fetched_at'>
      const cached: CachedCrl = { ...body, fetched_at: new Date().toISOString() }
      try {
        localStorage.setItem(CRL_KEY, JSON.stringify(cached))
      } catch {
        // quota — keep in-memory copy only
      }
      crl.current = cached
    } catch {
      // unreachable — stale cache stays in place
    }
  }

  useEffect(() => {
    loadCachedCrl()
    void refreshCrl()
    const tick = setInterval(() => void refreshCrl(), 5 * 60 * 1000)
    const goOffline = () => setOffline(true)
    const goOnline = () => setOffline(false)
    window.addEventListener('offline', goOffline)
    window.addEventListener('online', goOnline)
    return () => {
      clearInterval(tick)
      window.removeEventListener('offline', goOffline)
      window.removeEventListener('online', goOnline)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Auto-flush on mount (queued from a dead tab) and on reconnect.
  // `log` intentionally excluded — the query object is unstable and this
  // must run once (same shape as the bench live-refresh effect).
  useEffect(() => {
    void flushOutbox().then((r) => {
      if (r.sent > 0) {
        setOk(`Flushed ${r.sent} queued crossing${r.sent === 1 ? '' : 's'}`)
        log.refetch()
      }
    })
    const onOnline = () => {
      void flushOutbox().then((r) => {
        if (r.sent > 0 || r.dropped > 0) log.refetch()
      })
    }
    window.addEventListener('online', onOnline)
    return () => window.removeEventListener('online', onOnline)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function retryPending() {
    setFlushing(true)
    setNotice(null)
    try {
      const head = pending[0]
      if (head) {
        const { promise, resolve } = Promise.withResolvers<void>()
        setTimeout(resolve, retryDelayMs(head.attempts))
        await promise
      }
      const r = await flushOutbox()
      if (r.dropped > 0) setNotice(`${r.dropped} queued crossing(s) dropped — gate retired`)
      if (r.sent > 0) {
        setOk(`Flushed ${r.sent} queued crossing${r.sent === 1 ? '' : 's'}`)
        log.refetch()
      } else if (r.pending > 0 && r.dropped === 0) {
        setNotice(`Still offline — ${r.pending} crossing(s) waiting`)
      }
    } finally {
      setFlushing(false)
    }
  }
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
    let res: Response
    try {
      res = await apiFetch('/kyc/verify', { method: 'POST', body: JSON.stringify(parsed) })
    } catch {
      // Server unreachable: HMAC can't be recomputed. Cached CRL decides.
      verifyOffline(parsed)
      return
    }
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

  /// Offline verify: server unreachable, so the HMAC can't be recomputed.
  /// The cached CRL still identifies known-dead cards; anything else bounces
  /// to the audited manual override rather than pretending to verify.
  function verifyOffline(parsed: unknown): void {
    const appId =
      parsed !== null &&
      typeof parsed === 'object' &&
      'application_id' in parsed &&
      typeof parsed.application_id === 'string'
        ? parsed.application_id
        : ''
    const cached = crl.current
    if (cached && appId) {
      if (
        cached.revoked.some((r) => r.application_id === appId) ||
        cached.expired.some((r) => r.application_id === appId) ||
        cached.superseded.some((r) => r.application_id === appId)
      ) {
        setCard(null)
        setNotice('Offline (cached list): card is revoked, expired, or superseded — deny entry')
        return
      }
    }
    if (cached && Date.now() - Date.parse(cached.fetched_at) > 24 * 60 * 60 * 1000) {
      setNotice('Offline — cached deny list is over 24 h old; verify against it is stale')
      return
    }
    setCard(null)
    setNotice('Offline — signature cannot be verified. Admit via manual override (audited) or wait for reconnect')
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
    const payload = {
      siteId,
      gateId,
      direction,
      method,
      press_card: method === 'press_card' ? card : null,
      snapshot_key: snapshotKey || null,
    }
    let res: Response
    try {
      res = await apiFetch(`/sites/${siteId}/gates/${gateId}/events`, {
        method: 'POST',
        body: JSON.stringify(payload),
      })
    } catch {
      enqueueCrossing(payload)
      setNotice('Offline — crossing queued, will retry automatically')
      return
    }
    const body: unknown = await res.json().catch(() => ({}))
    if (!res.ok) {
      // Retryable transport-side failures queue; 4xx verdicts surface.
      // 410 (gate retired) drops immediately — nothing will ever succeed.
      if (res.status === 429 || res.status >= 500) {
        enqueueCrossing(payload)
        setNotice('Server busy — crossing queued, will retry automatically')
        return
      }
      if (res.status === 410) {
        setNotice('Gate retired — crossing refused, not queued')
        return
      }
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
    // Piggyback: a good connection flushes anything waiting.
    void flushOutbox().then((r) => {
      if (r.sent > 0) log.refetch()
    })
  }

  return (
    <section className="mt-8">
      <div className="flex items-baseline gap-3">
        <h2 className="text-2xl font-semibold tracking-tight">Gate kiosk</h2>
        {offline ? (
          <span className="border border-rose-200 bg-rose-50 px-2 py-0.5 text-xs font-medium text-rose-700">
            Offline{crl.current ? ' — cached deny list active' : ' — no cached deny list'}
          </span>
        ) : null}
        {pending.length > 0 ? (
          <span className="border border-saffron bg-saffron-mist px-2 py-0.5 text-xs font-medium text-saffron-ink">
            {pending.length} pending
          </span>
        ) : null}
        {pending.length > 0 ? (
          <button
            onClick={retryPending}
            disabled={flushing}
            className="border border-slate-300 bg-white px-2 py-0.5 text-xs font-medium disabled:opacity-50"
          >
            {flushing ? 'Retrying…' : 'Retry now'}
          </button>
        ) : null}
      </div>
      {pending.length > 0 ? (
        <details className="mt-2 font-ledger text-xs">
          <summary className="cursor-pointer uppercase">Queued crossings</summary>
          <ol className="mt-1 divide-y divide-neutral-200">
            {pending.map((p) => (
              <li key={p.id} className="py-1">
                <span className="uppercase">{p.direction}</span> · {p.method === 'press_card' ? 'card' : 'manual'}
                {p.method === 'press_card' && p.press_card ? ` — ${p.press_card.full_name}` : null}
                {' '}· {new Date(p.queued_at).toLocaleTimeString()} · try {p.attempts}
              </li>
            ))}
          </ol>
        </details>
      ) : null}
      {notice ? (
        <p role="alert" className="mt-3 border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-deny">
          {notice}
        </p>
      ) : null}
      {ok ? (
        <p className="mt-3 border border-ok bg-green-50 px-3 py-2 text-sm text-ok">{ok}</p>
      ) : null}
      <div className="mt-3 grid gap-4 md:grid-cols-2">
        <div className="border border-slate-200 rounded-xl bg-white shadow-sm p-4">
          <label className="flex flex-col gap-1 text-sm">
            Press-card payload (scanned QR JSON)
            <textarea
              className="border border-slate-300 bg-white px-3 py-2 font-ledger text-xs"
              rows={4}
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              placeholder='{"application_id": …}'
            />
          </label>
          <div className="mt-2 flex gap-2">
            <button onClick={verify} className="bg-signal px-4 py-2 text-sm font-medium text-white hover:bg-signal-deep">
              Verify card
            </button>
            <label className="flex flex-col gap-1 text-sm">
              Direction
              <select
                className="border border-slate-300 bg-white px-3 py-2"
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
              className="bg-ok px-4 py-2 text-sm font-medium text-white hover:bg-emerald-700"
            >
              Log card entry
            </button>
            <button
              onClick={() => record('manual')}
              className="border border-slate-300 bg-white px-4 py-2 text-sm font-medium align-middle hover:border-slate-400"
            >
              Log manual entry
            </button>
          </div>
        </div>
        <div className="border border-slate-200 rounded-xl bg-white shadow-sm p-4">
          <h3 className="text-base font-semibold tracking-tight">Recent crossings</h3>
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
                  <span className="font-semibold" title={e.holder_org ?? ''}>{e.holder_name}</span>
                ) : null}
                {e.snapshot_key ? (
                  <button
                    onClick={() => openPreview(e.snapshot_key)}
                    className="border-slate-300 bg-white px-1 text-xs font-medium"
                  >
                    Photo
                  </button>
                ) : null}
                <span className="ml-auto">{new Date(e.recorded_at).toLocaleTimeString()}</span>
              </li>
            ))}
          </ol>
          {preview ? (
            <div className="mt-2 border border-signal bg-white p-2">
              <img src={preview.url} alt={`Gate capture ${preview.key}`} className="max-h-64 w-auto" />
              <button onClick={() => setPreview(null)} className="mt-1 border-slate-300 bg-white px-2 py-1 text-xs font-medium align-middle hover:border-slate-400">
                Close
              </button>
            </div>
          ) : null}
        </div>
      </div>
    </section>
  )
}
