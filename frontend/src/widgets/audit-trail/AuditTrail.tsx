import { useState } from 'react'
import { apiFetch } from '@/shared/api'

interface AuditEntry {
  seq: number
  at: string
  actor: string | null
  action: string
  entity: string
  entity_id: string | null
  detail: unknown
}

function detailLines(detail: unknown): [string, string][] {
  if (detail === null || typeof detail !== 'object' || Array.isArray(detail)) return []
  return Object.keys(detail as Record<string, unknown>)
    .sort()
    .map((k) => {
      const v: unknown = (detail as Record<string, unknown>)[k]
      const text =
        v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
          ? String(v)
          : JSON.stringify(v)
      return [k, text]
    })
}

 export default function AuditTrail({ siteId, global }: { siteId: string | null; global?: boolean }) {
  const [rows, setRows] = useState<AuditEntry[] | null>(null)
  const [scope, setScope] = useState<'site' | 'all'>(global === true ? 'all' : 'site')
  const [verdict, setVerdict] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  async function load() {
    setNotice(null)
    const path = siteId ? `/sites/${siteId}/audit?limit=30` : '/audit?limit=30'
    const res = await apiFetch(path)
    if (!res.ok) {
      setNotice(`Trail would not load (${res.status})`)
      return
    }
    setRows((await res.json()) as AuditEntry[])
  }

  async function verify() {
    setNotice(null)
    const res = await apiFetch('/audit/verify')
    if (!res.ok) {
      setNotice(`Verify refused (${res.status})`)
      return
    }
    const body: unknown = await res.json()
    if (body !== null && typeof body === 'object' && 'ok' in body && 'checked' in body) {
      const ok: unknown = body.ok
      const checked: unknown = body.checked
      const firstBad: unknown = 'first_bad' in body ? body.first_bad : null
      setVerdict(
        ok === true
          ? `Chain intact — ${typeof checked === 'number' ? checked : '?'} entries checked`
          : `CHAIN BROKEN at seq ${typeof firstBad === 'number' ? firstBad : '?'}`,
      )
    }
  }

  return (
    <section className="mt-8">
      <div className="flex items-baseline gap-3">
        <h2 className="text-2xl font-semibold tracking-tight">Audit trail</h2>
        {global === true ? (
          <button
            onClick={() => setScope(scope === 'all' ? 'site' : 'all')}
            className="border border-slate-300 bg-white px-3 py-1 text-xs font-medium hover:border-slate-400"
          >
            {scope === 'all' ? 'Site scope' : 'Global scope'}
          </button>
        ) : null}
        <button onClick={load} className="border border-slate-300 bg-white px-3 py-1 text-xs font-medium hover:border-slate-400">
          Load trail
        </button>
        <button onClick={verify} className="border border-slate-300 bg-white px-3 py-1 text-xs font-medium hover:border-slate-400">
          Verify chain
        </button>
      </div>
      {notice ? <p className="mt-2 text-sm text-deny">{notice}</p> : null}
      {verdict ? <p className="mt-2 font-ledger text-xs">{verdict}</p> : null}
      <ol className="mt-3 divide-y divide-slate-200 border border-slate-200 bg-white rounded-xl shadow-sm">
        {(rows ?? []).map((e) => {
          const lines = detailLines(e.detail)
          return (
            <li key={e.seq} className="px-4 py-2 font-ledger text-xs">
              <div className="flex items-baseline gap-3">
                <span className="text-neutral-400">#{e.seq}</span>
                <span className="uppercase">{e.action}</span>
                <span className="text-neutral-500">{e.entity}</span>
                <span className="ml-auto">{new Date(e.at).toLocaleString()}</span>
              </div>
              {lines.length > 0 ? (
                <details className="mt-1">
                  <summary className="cursor-pointer uppercase text-neutral-500">detail</summary>
                  <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3">
                    {lines.map(([k, v]) => (
                      <div key={k} className="contents">
                        <dt className="text-neutral-500">{k}</dt>
                        <dd className="break-all">{v}</dd>
                      </div>
                    ))}
                  </dl>
                </details>
              ) : null}
            </li>
          )
        })}
      </ol>
      {rows !== null && rows.length === 0 ? (
        <p className="mt-2 text-sm">No entries yet — actions append here.</p>
      ) : null}
    </section>
  )
}
