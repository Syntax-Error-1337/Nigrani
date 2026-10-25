import { useEffect, useState } from 'react'
import { Anchor, Link2, ShieldCheck, XCircle } from 'lucide-react'
import { safeApi } from '@/shared/api'

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
  try {
      setNotice(null)
      const path = siteId ? `/sites/${siteId}/audit?limit=30` : '/audit?limit=30'
      const res = await safeApi(path)
      if (!res.ok) {
        setNotice(`Trail would not load (${res.status})`)
        return
      }
      setRows((await res.json()) as AuditEntry[])
  } catch {
    setNotice('Network error — is the API running?')
  }
  }

  async function verify() {
    setNotice(null)
    const res = await safeApi('/audit/verify')
    if (!res.ok) {
      setNotice(`Verify refused (${res.status})`)
      return
    }
    const body: unknown = await res.json()
    if (body !== null && typeof body === 'object' && 'ok' in body && 'checked' in body) {
      const ok: unknown = body.ok
      const checked: unknown = body.checked
      const firstBad: unknown = 'first_bad' in body ? body.first_bad : null
      const anchoredOk: unknown = 'anchored_ok' in body ? body.anchored_ok : true
      const anchorsChecked: unknown = 'anchors_checked' in body ? body.anchors_checked : 0
      const anchorNote =
        anchorsChecked === 0 || typeof anchorsChecked !== 'number'
          ? ''
          : anchoredOk === true
            ? ` · ${anchorsChecked} anchor(s) hold`
            : ' · ANCHOR MISMATCH — history was rewritten'
      setVerdict(
        ok === true
          ? `Chain intact — ${typeof checked === 'number' ? checked : '?'} entries checked${anchorNote}`
          : `CHAIN BROKEN at seq ${typeof firstBad === 'number' ? firstBad : '?'}`,
      )
    }
  }

  async function anchor() {
    setNotice(null)
    const res = await safeApi('/audit/anchor', { method: 'POST' })
    if (!res.ok) {
      setNotice(`Anchor refused (${res.status})`)
      return
    }
    setVerdict('Chain head anchored — record the hash outside this system')
  }

  // Load on open (and on scope/site switch) — the panel should never sit blank.
  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, siteId])

  return (
    <section className="mt-8">
      <div className="flex items-baseline gap-3">
        {global === true ? (
          <button
            onClick={() => setScope(scope === 'all' ? 'site' : 'all')}
            className="btn btn-secondary"
          >
            {scope === 'all' ? 'Site scope' : 'Global scope'}
          </button>
        ) : null}
        <button onClick={load} className="btn btn-secondary">
          <Link2 className="h-3.5 w-3.5" /> Load trail
        </button>
        <button onClick={verify} className="btn btn-secondary">
          <ShieldCheck className="h-3.5 w-3.5" /> Verify chain
        </button>
        {global === true ? (
          <button onClick={anchor} className="btn btn-secondary">
            <Anchor className="h-3.5 w-3.5" /> Anchor head
          </button>
        ) : null}
      </div>
      {notice ? (
        <p role="alert" className="mt-2 flex items-center gap-2 text-sm text-deny">
          <XCircle className="h-4 w-4 shrink-0" /> {notice}
        </p>
      ) : null}
      {verdict ? (
        <p className={`mt-2 inline-block rounded-lg px-3 py-1.5 font-ledger text-xs ${
          verdict.startsWith('CHAIN BROKEN') || verdict.includes('ANCHOR MISMATCH')
            ? 'bg-rose-50 text-deny'
            : 'bg-emerald-50 text-ok'
        }`}>{verdict}</p>
      ) : null}
      <ol className="mt-3 card max-h-[36rem] overflow-y-auto divide-y divide-slate-100">
        {rows === null ? (
          <li className="p-2" aria-hidden="true">
            <span className="skeleton mb-2 h-9 w-full opacity-70" />
            <span className="skeleton mb-2 h-9 w-full opacity-50" />
            <span className="skeleton h-9 w-full opacity-40" />
          </li>
        ) : null}
        {(rows ?? []).map((e) => {
          const lines = detailLines(e.detail)
          return (
            <li key={e.seq} className="px-4 py-2 font-ledger text-xs transition-colors hover:bg-slate-50/70">
              <div className="flex items-baseline gap-3">
                <span className="text-slate-500">#{e.seq}</span>
                <span className="uppercase">{e.action}</span>
                <span className="text-slate-500">{e.entity}</span>
                <span className="ml-auto">{new Date(e.at).toLocaleString()}</span>
              </div>
              {lines.length > 0 ? (
                <details className="mt-1">
                  <summary className="cursor-pointer uppercase text-slate-500">detail</summary>
                  <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3">
                    {lines.map(([k, v]) => (
                      <div key={k} className="contents">
                        <dt className="text-slate-500">{k}</dt>
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
