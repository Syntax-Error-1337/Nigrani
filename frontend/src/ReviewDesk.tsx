import { useState } from 'react'
import { useDebounced } from './useDebounced'
import { useKycQueue, type KycApplication } from './api'
import { apiFetch } from './session'

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
  const [card, setCard] = useState<{ name: string; payload: string; qrUrl: string } | null>(null)

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
    const img = await apiFetch(`/kyc/applications/${app.id}/press-card.png`)
    if (!img.ok) {
      setNotice('Card payload ready, but QR image failed — use the JSON fallback')
      setCard({ name: app.full_name, payload, qrUrl: '' })
      return
    }
    const blob = await img.blob()
    setCard({ name: app.full_name, payload, qrUrl: URL.createObjectURL(blob) })
  }

  const rows = queue.data ?? []

  return (
    <section className="mt-8">
      <div className="flex items-baseline gap-3">
        <h2 className="font-display text-2xl uppercase">Press review desk</h2>
        <input
          className="border border-ink px-2 py-1 text-sm"
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
            className={`border-2 px-3 py-1 font-ledger text-xs uppercase ${
              tab === s ? 'border-signal bg-white' : 'border-ink bg-white'
            }`}
          >
            {s}
          </button>
        ))}
      </div>
      {notice ? (
        <p role="alert" className="mt-3 border border-deny bg-red-50 px-3 py-2 text-sm text-deny">
          {notice}
        </p>
      ) : null}
      {queue.isLoading ? <p className="mt-3">Loading queue…</p> : null}
      {queue.isError ? <p className="mt-3 text-deny">Queue would not load.</p> : null}
      {!queue.isLoading && rows.length === 0 ? (
        <p className="mt-3">No {tab} applications.</p>
      ) : null}
      <ol className="mt-3 divide-y-2 divide-ink border-y-2 border-ink bg-white">
        {rows.map((app) => (
          <li key={app.id} className="px-4 py-3">
            <div className="flex flex-wrap items-baseline gap-3">
              <span className="font-display text-xl uppercase">{app.full_name}</span>
              {app.photo_url ? (
                <button
                  onClick={() => openPhoto(app)}
                  className="border border-ink px-1 font-ledger text-xs uppercase"
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
                <span className="border border-signal bg-yellow-50 px-1 font-ledger text-xs uppercase" title="Prior decided applications share this document">
                  repeat ×{app.prior_decisions}
                </span>
              ) : null}
              {app.card_revoked_at ? (
                <span className="border border-deny bg-red-50 px-1 font-ledger text-xs uppercase text-deny" title={`Card revoked ${app.card_revoked_at}`}>
                  revoked
                </span>
              ) : null}
            </div>
            {tab === 'pending' ? (
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <input
                  className="border border-ink px-2 py-1 text-sm"
                  placeholder="Reason (required for rejection)"
                  value={note[app.id] ?? ''}
                  onChange={(e) => setNote({ ...note, [app.id]: e.target.value })}
                />
                <button
                  onClick={() => decide(app, 'approved')}
                  className="bg-ok px-3 py-1 text-sm uppercase text-white"
                >
                  Approve
                </button>
                <button
                  onClick={() => decide(app, 'rejected')}
                  className="bg-deny px-3 py-1 text-sm uppercase text-white"
                >
                  Reject
                </button>
              </div>
            ) : null}
            {tab === 'approved' ? (
              <div className="mt-2 flex flex-wrap items-center gap-2">
                {!app.card_revoked_at ? (
                  <button
                    onClick={() => issueCard(app)}
                    className="border border-ink px-3 py-1 font-ledger text-xs uppercase"
                  >
                    Issue press card
                  </button>
                ) : null}
                {!app.card_revoked_at ? (
                  <button
                    onClick={() => revoke(app)}
                    className="bg-deny px-3 py-1 font-ledger text-xs uppercase text-white"
                  >
                    Revoke card
                  </button>
                ) : null}
              </div>
            ) : null}
          </li>
        ))}
      </ol>
      {photo ? (
        <div className="mt-4 border-2 border-signal bg-white p-2">
          <p className="font-display text-lg uppercase">Photo — {photo.name}</p>
          <img src={photo.url} alt={`Applicant photo for ${photo.name}`} className="mt-1 max-h-64 w-auto" />
          <button onClick={() => setPhoto(null)} className="mt-1 border border-ink px-2 py-1 font-ledger text-xs uppercase">
            Close
          </button>
        </div>
      ) : null}
      {card ? (
        <div className="mt-4 flex gap-4 border-2 border-signal bg-white p-4">
          {card.qrUrl ? (
            <img src={card.qrUrl} alt={`Press card QR for ${card.name}`} className="h-48 w-48 border border-ink" />
          ) : null}
          <div>
            <p className="font-display text-lg uppercase">Press card — {card.name}</p>
            <p className="mt-1 font-ledger text-xs break-all">{card.payload}</p>
            <p className="mt-2 text-sm">
              Scan the QR at the gate; the JSON fallback covers damaged prints.
            </p>
          </div>
        </div>
      ) : null}
    </section>
  )
}
