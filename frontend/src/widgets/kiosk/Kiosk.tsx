import { useEffect, useRef, useState } from 'react'
import { ArrowDownLeft, ArrowUpRight, Camera, CheckCircle2, ClipboardPaste, CornerDownLeft, History, ImageOff, RefreshCw, ScanLine, ScanSearch, Upload, XCircle } from 'lucide-react'
import { apiFetch } from '@/shared/api'
import { useGateLog } from '@/entities/gate-log'
import { useGates } from '@/entities/site'
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
/// Server `reason` → string-table key (stable API; server messages are
/// literal constants quoted in backend tests).
type DenialKey = 'denyRevoked' | 'denyPending' | 'denyExpired' | 'denySuperseded' | 'denyForged'
function denialKey(reason: unknown): DenialKey | null {
  if (reason === 'revoked') return 'denyRevoked'
  if (reason === 'not_approved') return 'denyPending'
  if (reason === 'expired') return 'denyExpired'
  if (reason === 'superseded') return 'denySuperseded'
  if (reason === 'bad_signature') return 'denyForged'
  return null
}

/// Record-time refusal mirrors the same copy.
function recordDenialKey(serverMessage: string): DenialKey | null {
  if (serverMessage.includes('at capacity')) return null // handled inline (untranslated)
  if (serverMessage.includes('press card revoked')) return 'denyRevoked'
  if (serverMessage.includes('not approved')) return 'denyPending'
  if (serverMessage.includes('press card expired')) return 'denyExpired'
  if (serverMessage.includes('press card superseded')) return 'denySuperseded'
  if (serverMessage.includes('failed verification')) return 'denyForged'
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


/// Kiosk operator strings — Hindi/English toggle (s-I2). Notices and
/// denial copy included; the machine-facing log labels stay English.
const KIOSK_STRINGS = {
  en: {
    title: 'Gate kiosk',
    offline: 'Offline',
    cachedList: 'cached deny list active',
    noList: 'no cached deny list',
    pending: 'pending',
    retryNow: 'Retry now',
    retrying: 'Retrying…',
    waiting: 'Waiting…',
    payloadLabel: 'Press-card payload (scanned QR JSON)',
    verifyCard: 'Verify card',
    direction: 'Direction',
    entry: 'Entry',
    exit: 'Exit',
    snapshotLabel: 'Snapshot (JPEG ≤ 5MB)',
    staged: 'staged:',
    openCapture: 'open capture',
    logCard: 'Log card entry',
    logManual: 'Log manual entry',
    recent: 'Recent crossings',
    loading: 'Loading log…',
    empty: 'No crossings recorded at this gate yet.',
    queued: 'Queued crossings',
    try: 'try',
    denyRevoked: 'Card revoked — redirect holder to the press desk',
    denyPending: 'Application not approved — redirect to accreditation',
    denyExpired: 'Card expired — redirect holder to the press desk for reissue',
    denySuperseded: 'Card superseded by a newer print — deny entry',
    denyForged: 'Card signature invalid — deny entry',
    offlineKnownDead: 'Offline (cached list): card is revoked, expired, or superseded — deny entry',
    offlineStale: 'Offline — cached deny list is over 24 h old; verify against it is stale',
    offlineManual: 'Offline — signature cannot be verified. Admit via manual override (audited) or wait for reconnect',
    queuedOffline: 'Offline — crossing queued, will retry automatically',
    queuedBusy: 'Server busy — crossing queued, will retry automatically',
    gateRetired: 'Gate retired — crossing refused, not queued',
    flushed: (n: number) => `Flushed ${n} queued crossing${n === 1 ? '' : 's'}`,
    dropped: (n: number) => `${n} queued crossing(s) dropped — gate retired`,
    stillOffline: (n: number) => `Still offline — ${n} crossing(s) waiting`,
  },
  hi: {
    title: 'गेट कियोस्क',
    offline: 'ऑफ़लाइन',
    cachedList: 'कैश्ड डिनाई सूची सक्रिय',
    noList: 'कोई कैश्ड डिनाई सूची नहीं',
    pending: 'लंबित',
    retryNow: 'अभी पुनः प्रयास',
    retrying: 'पुनः प्रयास…',
    waiting: 'प्रतीक्षा…',
    payloadLabel: 'प्रेस-कार्ड पेलोड (स्कैन किया QR JSON)',
    verifyCard: 'कार्ड सत्यापित करें',
    direction: 'दिशा',
    entry: 'प्रवेश',
    exit: 'निर्गम',
    snapshotLabel: 'स्नैपशॉट (JPEG ≤ 5MB)',
    staged: 'स्टेज्ड:',
    openCapture: 'कैप्चर खोलें',
    logCard: 'कार्ड प्रवेश दर्ज करें',
    logManual: 'मैनुअल प्रवेश दर्ज करें',
    recent: 'हाल के क्रॉसिंग',
    loading: 'लॉग लोड हो रहा है…',
    empty: 'इस गेट पर अभी कोई क्रॉसिंग दर्ज नहीं है।',
    queued: 'कतार में क्रॉसिंग',
    try: 'प्रयास',
    denyRevoked: 'कार्ड निरस्त — धारक को प्रेस डेस्क भेजें',
    denyPending: 'आवेदन स्वीकृत नहीं — प्रेस डेस्क भेजें',
    denyExpired: 'कार्ड समाप्त — नए कार्ड हेतु प्रेस डेस्क भेजें',
    denySuperseded: 'नए प्रिंट द्वारा प्रतिस्थापित — प्रवेश निषेध',
    denyForged: 'कार्ड हस्ताक्षर अवैध — प्रवेश निषेध',
    offlineKnownDead: 'ऑफ़लाइन (कैश्ड सूची): कार्ड निरस्त/समाप्त/प्रतिस्थापित — प्रवेश निषेध',
    offlineStale: 'ऑफ़लाइन — कैश्ड डिनाई सूची 24 घंटे से पुरानी; सत्यापन अविश्वसनीय',
    offlineManual: 'ऑफ़लाइन — हस्ताक्षर सत्यापित नहीं हो सकता। मैनुअल ओवरराइड (लेखा-जोखा) से प्रवेश दें या पुनः कनेक्ट की प्रतीक्षा करें',
    queuedOffline: 'ऑफ़लाइन — क्रॉसिंग कतार में, स्वतः पुनः प्रयास होगा',
    queuedBusy: 'सर्वर व्यस्त — क्रॉसिंग कतार में, स्वतः पुनः प्रयास होगा',
    gateRetired: 'गेट सेवामुक्त — क्रॉसिंग अस्वीकृत, कतार में नहीं',
    flushed: (n: number) => `${n} कतारबद्ध क्रॉसिंग भेजी गईं`,
    dropped: (n: number) => `${n} कतारबद्ध क्रॉसिंग हटाई गईं — गेट सेवामुक्त`,
    stillOffline: (n: number) => `अभी ऑफ़लाइन — ${n} क्रॉसिंग प्रतीक्षारत`,
  },
} as const
type KioskLang = keyof typeof KIOSK_STRINGS

export default function Kiosk({
  siteId,
  gateId,
  onPickGate,
}: {
  siteId: string | null
  gateId: string | null
  // DutyPanel fixes the post; the kiosk section exposes the picker.
  onPickGate?: (id: string) => void
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
  const [lang, setLang] = useState<KioskLang>(
    () => ((localStorage.getItem('sg-lang') as KioskLang) ?? 'en'),
  )
  const t = KIOSK_STRINGS[lang]
  const log = useGateLog(siteId, gateId)
  const gates = useGates(siteId, '')
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
        setOk(t.flushed(r.sent))
        log.refetch()
      }
    })
    const onOnline = () => {
      setOffline(false)
      void flushOutbox().then((r) => {
        if (r.sent > 0) {
          setOk(t.flushed(r.sent))
          setNotice(null) // stale queuedOffline banner
          log.refetch()
        } else if (r.dropped > 0) {
          setNotice(t.dropped(r.dropped))
          log.refetch()
        }
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
      if (r.dropped > 0) setNotice(t.dropped(r.dropped))
      if (r.sent > 0) {
        setOk(t.flushed(r.sent))
        log.refetch()
      } else if (r.pending > 0 && r.dropped === 0) {
        setNotice(t.stillOffline(r.pending))
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
      const key = denialKey(reason)
      setNotice(key ? t[key] : t.denyForged)
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
        setNotice(t.offlineKnownDead)
        return
      }
    }
    if (cached && Date.now() - Date.parse(cached.fetched_at) > 24 * 60 * 60 * 1000) {
      setNotice(t.offlineStale)
      return
    }
    setCard(null)
    setNotice(t.offlineManual)
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
      setNotice(t.queuedOffline)
      return
    }
    const body: unknown = await res.json().catch(() => ({}))
    if (!res.ok) {
      // Retryable transport-side failures queue; 4xx verdicts surface.
      // 410 (gate retired) drops immediately — nothing will ever succeed.
      if (res.status === 429 || res.status >= 500) {
        enqueueCrossing(payload)
        setNotice(t.queuedBusy)
        return
      }
      if (res.status === 410) {
        setNotice(t.gateRetired)
        return
      }
      const raw =
        body !== null && typeof body === 'object' && 'error' in body && typeof body.error === 'string'
          ? body.error
          : ''
      const key = recordDenialKey(raw)
      setNotice(key ? t[key] : apiError(body, 'Could not record entry'))
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
      <div className="flex flex-wrap items-center gap-3">
        {onPickGate ? (
          <label className="flex items-center gap-1.5 text-sm">
            <span className="text-xs text-slate-500">Gate post</span>
            <select
              aria-label="Gate post"
              className="input !w-auto !py-1 !text-xs"
              value={gateId ?? ''}
              onChange={(e) => onPickGate(e.target.value)}
            >
              <option value="" disabled>pick a post…</option>
              {(gates.data ?? []).filter((g) => !g.archived_at).map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name} ({g.direction})
                </option>
              ))}
            </select>
          </label>
        ) : null}
        {gateId === null ? (
          <span className="pill pill-warn">no gate post selected</span>
        ) : null}
        {offline ? (
          <span className="pill pill-archived">
            {t.offline} — {crl.current ? t.cachedList : t.noList}
          </span>
        ) : null}
        <button
          onClick={() => {
            const next: KioskLang = lang === 'en' ? 'hi' : 'en'
            setLang(next)
            localStorage.setItem('sg-lang', next)
          }}
          className="btn btn-secondary !px-2 !py-0.5 text-xs"
        >
          {lang === 'en' ? 'हिंदी' : 'English'}
        </button>
        {pending.length > 0 ? (
          <span className="pill border border-saffron bg-saffron-mist text-saffron-ink">
            {pending.length} {t.pending}
          </span>
        ) : null}
        {pending.length > 0 ? (
          <button
            onClick={retryPending}
            disabled={flushing}
            className="btn btn-secondary !px-2 !py-0.5 text-xs disabled:opacity-50"
          >
            <RefreshCw className={`h-3 w-3 ${flushing ? 'animate-spin' : ''}`} />
            {flushing ? t.retrying : t.retryNow}
          </button>
        ) : null}
      </div>
      {pending.length > 0 ? (
        <details className="mt-2 font-ledger text-xs">
          <summary className="cursor-pointer uppercase text-slate-600 transition-colors hover:text-signal">
            {t.queued} ({pending.length})
          </summary>
          <ol className="mt-1 divide-y divide-slate-100">
            {pending.map((p) => (
              <li key={p.id} className="flex items-center gap-2 py-1">
                <span className="rounded bg-slate-100 px-1.5 py-0.5 uppercase">{p.direction}</span>
                <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] uppercase">{p.method === 'press_card' ? 'card' : 'manual'}</span>
                {p.method === 'press_card' && p.press_card ? <span className="truncate font-semibold">{p.press_card.full_name}</span> : null}
                <span className="tabular-nums text-slate-500">{new Date(p.queued_at).toLocaleTimeString()}</span>
                <span className="text-slate-500">{t.try} {p.attempts}</span>
              </li>
            ))}
          </ol>
        </details>
      ) : null}
      {notice ? (
        <p role="alert" className="mt-3 flex items-start gap-2 rounded-xl border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-deny">
          <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
          {notice}
        </p>
      ) : null}
      {ok ? (
        <p className="mt-3 flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-ok">
          <CheckCircle2 className="h-4 w-4 shrink-0" />
          {ok}
        </p>
      ) : null}
      {card && ok ? (
        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 rounded-xl border border-emerald-200 bg-emerald-50/60 px-3 py-2 font-ledger text-xs text-ink">
          <span className="font-semibold">{card.full_name}</span>
          {card.organization ? <span className="text-slate-500">{card.organization}</span> : null}
          {card.serial ? <span>serial {card.serial}</span> : null}
          {card.expires_at ? (
            <span className="text-slate-500">valid until {new Date(card.expires_at).toLocaleDateString()}</span>
          ) : null}
        </div>
      ) : null}
      {gateId === null ? (
        <p className="mt-8 text-center text-sm text-slate-500">
          <ScanLine className="mx-auto h-5 w-5" />
          <span className="mt-1 block">Pick a gate post above to start screening.</span>
        </p>
      ) : (
      <div className="mt-3 grid gap-4 md:grid-cols-2">
        <div className="card p-4">
          <label className="flex flex-col gap-1 text-sm">
            <span className="flex items-center gap-1.5">
              <ClipboardPaste className="h-3.5 w-3.5 text-slate-400" />
              {t.payloadLabel}
            </span>
            <textarea
              className="input font-ledger text-xs"
              rows={4}
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
                  e.preventDefault()
                  void verify()
                }
              }}
              placeholder='{"application_id": …}'
            />
          </label>
          <div className="mt-2 flex gap-2">
            <button onClick={verify} className="btn btn-primary">
              <ScanSearch className="h-3.5 w-3.5" />
              {t.verifyCard}
            </button>
            <label className="flex flex-col gap-1 text-sm">
              {t.direction}
              <select
                className="input"
                value={direction}
                onChange={(e) => setDirection(e.target.value as 'entry' | 'exit')}
              >
                <option value="entry">{t.entry}</option>
                <option value="exit">{t.exit}</option>
              </select>
            </label>
          </div>
          <div className="mt-3 flex flex-col gap-1 text-sm">
            <span className="flex items-center gap-1.5">
              <Camera className="h-3.5 w-3.5 text-slate-400" />
              {t.snapshotLabel}
            </span>
            <label
              className={`flex cursor-pointer items-center justify-center gap-2 rounded-xl border border-dashed border-slate-300 bg-slate-50/70 px-3 py-2.5 text-sm text-slate-500 transition-colors hover:border-signal hover:bg-blue-50/50 hover:text-signal ${uploading ? 'pointer-events-none opacity-60' : ''}`}
            >
              {uploading ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />}
              {uploading ? t.waiting : 'Choose file or drop'}
              <input
                type="file"
                accept="image/jpeg"
                className="sr-only"
                disabled={uploading}
                onChange={(e) => {
                  const f = e.target.files?.[0]
                  if (f) uploadSnapshot(f)
                }}
              />
            </label>
          </div>
          {snapshotKey ? (
            <p className="mt-1 flex items-center gap-1.5 font-ledger text-xs">
              <span className="rounded border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-ok">{t.staged}</span>
              <span className="truncate">{snapshotKey}</span>
              {shareUrl ? (
                <a className="shrink-0 underline transition-colors hover:text-signal" href={shareUrl} target="_blank" rel="noreferrer">
                  {t.openCapture}
                </a>
              ) : null}
            </p>
          ) : null}
          <div className="mt-3 flex gap-2">
            <button
              onClick={() => record('press_card')}
              className="btn btn-success"
            >
              <ArrowDownLeft className="h-3.5 w-3.5" />
              {t.logCard}
            </button>
            <button
              onClick={() => record('manual')}
              className="btn btn-secondary"
            >
              <CornerDownLeft className="h-3.5 w-3.5" />
              {t.logManual}
            </button>
          </div>
        </div>
        <div className="card p-4">
          <h2 className="flex items-center gap-1.5 text-base font-semibold tracking-tight">
            <History className="h-4 w-4 text-slate-400" />
            {t.recent}
          </h2>
          {log.isLoading ? (
            <ol className="mt-2" aria-hidden="true">
              <li><span className="skeleton mb-2 h-5 w-full opacity-70" /></li>
              <li><span className="skeleton mb-2 h-5 w-4/5 opacity-50" /></li>
              <li><span className="skeleton h-5 w-3/5 opacity-40" /></li>
            </ol>
          ) : null}
          {(log.data ?? []).length === 0 && !log.isLoading ? (
            <p className="mt-6 text-center text-sm text-slate-500">
              <ImageOff className="mx-auto h-5 w-5" />
              <span className="mt-1 block">{t.empty}</span>
            </p>
          ) : null}
          <ol className="mt-2 divide-y divide-slate-100">
            {(log.data ?? []).map((e) => (
              <li key={e.id} className="flex items-center gap-2 rounded-lg px-2 py-1.5 font-ledger text-xs transition-colors hover:bg-slate-50/70">
                <span className="flex w-20 shrink-0 items-center gap-1 uppercase">
                  {e.direction === 'exit'
                    ? <ArrowUpRight className="h-3 w-3 text-slate-400" />
                    : <ArrowDownLeft className="h-3 w-3 text-signal" />}
                  {e.direction}
                </span>
                <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium uppercase text-slate-600">
                  {e.method === 'press_card' ? 'card' : 'manual'}
                </span>
                {e.holder_name ? (
                  <span className="truncate font-semibold" title={e.holder_org ?? ''}>{e.holder_name}</span>
                ) : null}
                {e.snapshot_key ? (
                  <button
                    onClick={() => openPreview(e.snapshot_key)}
                    className="btn-chip ml-auto shrink-0"
                  >
                    <Camera className="h-3 w-3" /> Photo
                  </button>
                ) : null}
                <span className={`${e.snapshot_key ? '' : 'ml-auto'} shrink-0 tabular-nums text-slate-500`}>{new Date(e.recorded_at).toLocaleTimeString()}</span>
              </li>
            ))}
          </ol>
          {preview ? (
            <div className="mt-2 rounded-xl border border-signal bg-white p-2 shadow-md">
              <img src={preview.url} alt={`Gate capture ${preview.key}`} className="max-h-64 rounded-lg w-auto" />
              <button onClick={() => setPreview(null)} className="btn-chip mt-2">Close</button>
            </div>
          ) : null}
        </div>
      </div>
      )}
    </section>
  )
}
