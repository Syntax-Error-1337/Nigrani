import { useState } from 'react'
import { Ban, Check, Download, IdCard, Inbox, RefreshCcw, X, XCircle } from 'lucide-react'
import { useDebounced } from '@/shared/lib'
import { useKycQueue, type KycApplication, type PressCard } from '@/entities/kyc'
import { apiFetch } from '@/shared/api'

function queueError(body: unknown, fallback: string): string {
  if (body !== null && typeof body === 'object' && 'error' in body) {
    const err: unknown = body.error
    if (typeof err === 'string' && err.length > 0) return err
  }
  return fallback
}

export default function ReviewDesk() {
  const [tab, setTab] = useState('pending')
  const [search, setSearch] = useState('')
  const queue = useKycQueue(tab, useDebounced(search))
  const [note, setNote] = useState<Record<string, string>>({})
  const [notice, setNotice] = useState<string | null>(null)
  const [photo, setPhoto] = useState<{ name: string; url: string } | null>(null)
  const [card, setCard] = useState<{
    name: string
    payload: string
    qrUrl: string
    serial: string | null
    expires: string | null
  } | null>(null)

  async function decide(app: KycApplication, decision: 'approved' | 'rejected') {
    setNotice(null)
    if (decision === 'rejected' && (note[app.id] ?? '').trim().length < 3) {
      setNotice('Add a reason first — rejections need recourse')
      return
    }
    const res = await apiFetch(`/kyc/applications/${app.id}/decide`, {
      method: 'POST',
      body: JSON.stringify({ decision, note: note[app.id] ?? '' }),
    })
    if (!res.ok) {
      setNotice(queueError(await res.json().catch(() => ({})), `Could not ${decision} ${app.full_name}`))
      return
    }
    queue.refetch()
  }

  async function revoke(app: KycApplication) {
    setNotice(null)
    const res = await apiFetch(`/kyc/applications/${app.id}/revoke-card`, { method: 'POST' })
    if (!res.ok) {
      setNotice(queueError(await res.json().catch(() => ({})), `Could not revoke ${app.full_name}`))
      return
    }
    queue.refetch()
  }

  async function reissue(app: KycApplication) {
    setNotice(null)
    const res = await apiFetch(`/kyc/applications/${app.id}/reissue`, { method: 'POST' })
    if (!res.ok) {
      setNotice(queueError(await res.json().catch(() => ({})), `Could not reissue ${app.full_name}`))
      return
    }
    queue.refetch()
  }

  async function downloadCrl() {
    setNotice(null)
    const res = await apiFetch('/kyc/crl')
    if (!res.ok) {
      setNotice(`CRL export refused (${res.status})`)
      return
    }
    const blob = await res.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `crl-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  async function openPhoto(app: KycApplication) {
    setNotice(null)
    setPhoto(null)
    const ref = app.photo_url
    if (ref.startsWith('http://') || ref.startsWith('https://')) {
      setPhoto({ name: app.full_name, url: ref })
      return
    }
    // Otherwise treat as a snapshot key (UUID.jpg): presigned fetch.
    const key = ref.startsWith('s3://') ? ref.slice(5) : ref
    const res = await apiFetch(`/snapshots/${key}/share`)
    if (!res.ok) {
      setNotice('Photo unavailable')
      return
    }
    const body: unknown = await res.json().catch(() => ({}))
    if (body !== null && typeof body === 'object' && 'url' in body && typeof body.url === 'string') {
      setPhoto({ name: app.full_name, url: body.url })
    }
  }

  async function issueCard(app: KycApplication) {
    setNotice(null)
    setCard(null)
    const res = await apiFetch(`/kyc/applications/${app.id}/press-card`)
    if (!res.ok) {
      setNotice(queueError(await res.json().catch(() => ({})), 'Could not issue press card'))
      return
    }
    const payload = await res.text()
    // Issuing mints the serial/expiry server-side; refresh the queue row.
    queue.refetch()
    const parsed = JSON.parse(payload) as Partial<PressCard>
    const img = await apiFetch(`/kyc/applications/${app.id}/press-card.png`)
    if (!img.ok) {
      setNotice('Card payload ready, but QR image failed — use the JSON fallback')
      setCard({ name: app.full_name, payload, qrUrl: '', serial: parsed.serial ?? null, expires: parsed.expires_at ?? null })
      return
    }
    const blob = await img.blob()
    setCard({ name: app.full_name, payload, qrUrl: URL.createObjectURL(blob), serial: parsed.serial ?? null, expires: parsed.expires_at ?? null })
  }

  const rows = queue.data ?? []

  return (
    <section className="mt-8">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-semibold tracking-tight">Press review desk</h2>
        <input
          className="input ml-auto w-56"
          placeholder="Search applicants…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>
      <div className="mt-3 flex gap-2">
        {['pending', 'approved', 'rejected'].map((s) => (
          <button
            key={s}
            onClick={() => setTab(s)}
            className={`rounded-full px-3 py-1 text-xs font-medium ${
              tab === s
                ? 'bg-navy text-white shadow-sm'
                : 'bg-white border border-slate-300 text-slate-600 hover:border-slate-400'
            }`}
          >
            {s}
          </button>
        ))}
      </div>
      {notice ? (
        <p role="alert" className="mt-3 flex items-start gap-2 rounded-xl border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-deny">
          <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
          {notice}
        </p>
      ) : null}
      {queue.isLoading ? <p className="mt-3">Loading queue…</p> : null}
      {queue.isError ? <p className="mt-3 text-deny">Queue would not load.</p> : null}
      {!queue.isLoading && rows.length === 0 ? (
        <p className="mt-8 text-center text-sm text-slate-400">
          <Inbox className="mx-auto h-5 w-5" />
          <span className="mt-1 block">No {tab} applications.</span>
        </p>
      ) : null}
      <ol className="mt-3 card divide-y divide-slate-100">
        {rows.map((app) => (
          <li key={app.id} className="px-4 py-3 transition-colors hover:bg-slate-50/70">
            <div className="flex flex-wrap items-baseline gap-3">
              <span className="text-lg font-semibold tracking-tight">{app.full_name}</span>
              {app.photo_url ? (
                <button
                  onClick={() => openPhoto(app)}
                  className="border-slate-300 bg-white px-1 text-xs font-medium"
                >
                  Photo
                </button>
              ) : null}
              <span className="font-ledger text-xs text-neutral-500">
                {app.organization || '—'} · {app.document_type} {app.document_number}
              </span>
              {app.decision_note ? (
                <span className="font-ledger text-xs">note: {app.decision_note}</span>
              ) : null}
              {(app.prior_decisions ?? 0) > 0 ? (
                <span className="pill border border-saffron bg-saffron-mist text-saffron-ink" title="Prior decided applications share this document">
                  repeat ×{app.prior_decisions}
                </span>
              ) : null}
              {(app.duplicates ?? []).map((f) => (
                <span
                  key={`${f.similar_id}-${f.reason}`}
                  className="pill border border-saffron bg-saffron-mist text-saffron-ink"
                  title={`Possible duplicate of ${f.similar_id.slice(0, 8)} — ${f.reason} similarity ${f.score.toFixed(2)}`}
                >
                  dup? {f.reason} {f.score.toFixed(2)}
                </span>
              ))}
              {app.card_revoked_at ? (
                <span className="pill pill-archived" title={`Card revoked ${app.card_revoked_at}`}>
                  revoked
                </span>
              ) : null}
            </div>
            {tab === 'pending' ? (
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <input
                  className="input min-w-56 flex-1"
                  placeholder="Reason (required for rejection)"
                  value={note[app.id] ?? ''}
                  onChange={(e) => setNote({ ...note, [app.id]: e.target.value })}
                />
                <button
                  onClick={() => decide(app, 'approved')}
                  className="btn btn-success"
                >
                  <Check className="h-3.5 w-3.5" /> Approve
                </button>
                <button
                  onClick={() => decide(app, 'rejected')}
                  className="btn btn-danger"
                >
                  <X className="h-3.5 w-3.5" /> Reject
                </button>
              </div>
            ) : null}
            {tab === 'approved' ? (
              <div className="mt-2 flex flex-wrap items-center gap-2">
                {!app.card_revoked_at ? (
                  <button
                    onClick={() => issueCard(app)}
                    className="btn btn-secondary"
                  >
                    <IdCard className="h-3.5 w-3.5" /> Issue press card
                  </button>
                ) : null}
                {!app.card_revoked_at ? (
                  <button
                    onClick={() => reissue(app)}
                    className="btn btn-secondary"
                    title="Rotate the serial and refresh the 90-day validity; old prints stop scanning"
                  >
                    <RefreshCcw className="h-3.5 w-3.5" /> Reissue card
                  </button>
                ) : null}
                {!app.card_revoked_at ? (
                  <button
                    onClick={() => revoke(app)}
                    className="btn btn-danger"
                  >
                    <Ban className="h-3.5 w-3.5" /> Revoke card
                  </button>
                ) : null}
                {app.card_serial && !app.card_revoked_at ? (
                  <span className="font-ledger text-xs text-neutral-500">
                    Serial {app.card_serial} · prints {app.card_print_count}
                    {app.card_expires_at
                      ? ` · valid until ${new Date(app.card_expires_at).toLocaleDateString()}`
                      : ''}
                  </span>
                ) : null}
              </div>
            ) : null}
          </li>
        ))}
      </ol>
      <div className="mt-3 flex items-baseline gap-3">
        <button onClick={downloadCrl} className="btn btn-secondary">
          <Download className="h-3.5 w-3.5" /> Download CRL
        </button>
        <span className="text-xs text-neutral-500">
          Revoked, expired, and superseded serials — offline JSON for gate checks.
        </span>
      </div>
      {photo ? (
        <div className="mt-4 border border-signal bg-white p-2">
          <p className="text-base font-semibold tracking-tight">Photo — {photo.name}</p>
          <img src={photo.url} alt={`Applicant photo for ${photo.name}`} className="mt-1 max-h-64 w-auto" />
          <button onClick={() => setPhoto(null)} className="mt-1 border border-slate-300 bg-white px-2 py-1 text-xs font-medium hover:border-slate-400">
            Close
          </button>
        </div>
      ) : null}
      {card ? (
        <div className="mt-4 flex gap-4 border border-signal bg-white p-4">
          {card.qrUrl ? (
            <img src={card.qrUrl} alt={`Press card QR for ${card.name}`} className="h-48 w-48 rounded-lg border border-slate-200" />
          ) : null}
          <div>
            <p className="text-base font-semibold tracking-tight">Press card — {card.name}</p>
            <p className="mt-1 font-ledger text-xs break-all">{card.payload}</p>
            {card.serial ? (
              <p className="mt-1 text-sm">
                Serial {card.serial}
                {card.expires ? ` · valid until ${new Date(card.expires).toLocaleDateString()}` : ''}
              </p>
            ) : null}
            <p className="mt-2 text-sm">
              Scan the QR at the gate; the JSON fallback covers damaged prints.
            </p>
          </div>
        </div>
      ) : null}
    </section>
  )
}
