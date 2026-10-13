import { useState } from 'react'
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
  const queue = useKycQueue(tab)
  const [note, setNote] = useState<Record<string, string>>({})
  const [notice, setNotice] = useState<string | null>(null)
  const [card, setCard] = useState<{ name: string; payload: string; qrUrl: string } | null>(null)

  async function decide(app: KycApplication, decision: 'approved' | 'rejected') {
    setNotice(null)
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
      <h2 className="font-display text-2xl uppercase">Press review desk</h2>
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
              <span className="font-ledger text-xs text-neutral-500">
                {app.organization || '—'} · {app.document_type} {app.document_number}
              </span>
              {app.decision_note ? (
                <span className="font-ledger text-xs">note: {app.decision_note}</span>
              ) : null}
            </div>
            {tab === 'pending' ? (
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <input
                  className="border border-ink px-2 py-1 text-sm"
                  placeholder="Decision note (optional)"
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
              <button
                onClick={() => issueCard(app)}
                className="mt-2 border border-ink px-3 py-1 font-ledger text-xs uppercase"
              >
                Issue press card
              </button>
            ) : null}
          </li>
        ))}
      </ol>
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
