import { useEffect, useState } from 'react'
import {  } from 'lucide-react'
import { apiFetch } from '@/shared/api'

interface Policy {
  entity: string
  retain_days: number
}

export default function RetentionPanel({ siteId }: { siteId: string | null }) {
  const [policies, setPolicies] = useState<Policy[] | null>(null)
  const [report, setReport] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [orphans, setOrphans] = useState<{ count: number; referenced: number; sample: string[] } | null>(null)
  const [collected, setCollected] = useState<number | null>(null)
  async function exportSite() {
    setNotice(null)
    setReport(null)
    if (siteId === null) {
      setNotice('Select a site scope first')
      return
    }
    const res = await apiFetch(`/sites/${siteId}/export`)
    if (!res.ok) {
      setNotice(`Export refused (${res.status})`)
      return
    }
    const blob = await res.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `site-${siteId}-export.json`
    a.click()
    URL.revokeObjectURL(a.href)
    setReport('Site export downloaded')
  }

  async function downloadCsv() {
    setNotice(null)
    if (siteId === null) {
      setNotice('Select a site scope first')
      return
    }
    const res = await apiFetch(`/sites/${siteId}/report.csv`)
    if (!res.ok) {
      setNotice(`CSV refused (${res.status})`)
      return
    }
    const blob = await res.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `site-${siteId}-daily.csv`
    a.click()
    URL.revokeObjectURL(a.href)
    setReport('Daily CSV downloaded')
  }
  async function load() {
    setNotice(null)
    const res = await apiFetch('/admin/retention/policies')
    if (!res.ok) {
      setNotice(`Policies refused (${res.status})`)
      return
    }
    setPolicies((await res.json()) as Policy[])
  }

  async function save(entity: string, retain_days: number) {
    setNotice(null)
    const res = await apiFetch(`/admin/retention/policies/${entity}`, {
      method: 'POST',
      body: JSON.stringify({ retain_days }),
    })
    if (!res.ok) {
      setNotice(`Policy save failed (${res.status})`)
      return
    }
    load()
  }

  async function purge() {
    setNotice(null)
    setReport(null)
    const res = await apiFetch('/admin/retention/run', { method: 'POST' })
    if (!res.ok) {
      setNotice(`Purge refused (${res.status})`)
      return
    }
    const body: unknown = await res.json()
    if (body !== null && typeof body === 'object' && 'purged' in body) {
      const purged: unknown = body.purged
      if (purged !== null && typeof purged === 'object') {
        const parts = Object.entries(purged).map(([k, v]) => `${k}: ${typeof v === 'number' ? v : '?'}`)
        const extraKeys = ['snapshots_dereferenced', 'snapshots_deleted', 'snapshots_delete_failed'] as const
        for (const k of extraKeys) {
          const v: unknown = (body as Record<string, unknown>)[k]
          if (typeof v === 'number' && v > 0) parts.push(`${k}: ${v}`)
        }
        setReport(`Purged — ${parts.join(', ')}`)
        return
      }
    }
    setReport('Purge ran')
  }

  async function preview() {
    setNotice(null)
    setReport(null)
    const res = await apiFetch('/admin/retention/preview', { method: 'POST' })
    if (!res.ok) {
      setNotice(`Preview refused (${res.status})`)
      return
    }
    const body: unknown = await res.json()
    if (body !== null && typeof body === 'object' && 'purged' in body) {
      const purged: unknown = body.purged
      if (purged !== null && typeof purged === 'object') {
        const parts = Object.entries(purged).map(([k, v]) => `${k}: ${typeof v === 'number' ? v : '?'}`)
        const deref: unknown = (body as Record<string, unknown>).snapshots_dereferenced
        if (typeof deref === 'number' && deref > 0) parts.push(`snapshots_dereferenced: ${deref}`)
        setReport(`Would purge — ${parts.join(', ')}`)
        return
      }
    }
    setReport('Preview ran')
  }

  // Policies load on open — no blank panel waiting on a button.
  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function checkOrphans() {
    setCollected(null)
    const res = await apiFetch('/admin/snapshots/collect', {
      method: 'POST',
      body: JSON.stringify({ dry_run: true }),
    })
    if (!res.ok) {
      setNotice(res.status === 500 ? 'Snapshot storage unavailable' : `Orphan check refused (${res.status})`)
      return
    }
    const body = (await res.json()) as {
      orphan_count: number
      referenced_count: number
      orphans: string[]
    }
    setOrphans({ count: body.orphan_count, referenced: body.referenced_count, sample: body.orphans.slice(0, 8) })
  }

  async function collectOrphans() {
    setNotice(null)
    setCollected(null)
    const res = await apiFetch('/admin/snapshots/collect', {
      method: 'POST',
      body: JSON.stringify({ dry_run: false }),
    })
    if (!res.ok) {
      setNotice(res.status === 500 ? 'Snapshot storage unavailable' : `Collection refused (${res.status})`)
      return
    }
    const body = (await res.json()) as { deleted: number }
    setCollected(body.deleted)
    setOrphans(null)
  }
  return (
    <section className="mt-8">
      <div className="flex items-baseline gap-3">
        
        <button onClick={load} className="btn btn-secondary">
          Load policies
        </button>
        <button onClick={purge} className="border border-rose-200 bg-white px-3 py-1 text-xs font-medium text-deny hover:bg-rose-50">
          Run purge
        </button>
        <button onClick={preview} className="btn btn-secondary">
          Preview purge
        </button>
        <button onClick={exportSite} className="btn btn-secondary">
          Export active site
        </button>
        <button onClick={downloadCsv} className="btn btn-secondary">
          Daily CSV
        </button>
      </div>
      {notice ? <p className="mt-2 text-sm text-deny">{notice}</p> : null}
      {report ? <p className="mt-2 font-ledger text-xs">{report}</p> : null}
      {(policies ?? []).length > 0 ? (
        <table className="mt-2 w-full border border-slate-200 rounded-xl bg-white shadow-sm font-ledger text-xs">
          <thead>
            <tr className="text-left uppercase">
              <th className="px-3 py-1">Entity</th>
              <th className="px-3 py-1">Keep (days, 0 = forever)</th>
              <th className="px-3 py-1"></th>
            </tr>
          </thead>
          <tbody>
            {(policies ?? []).map((p) => (
              <PolicyRow key={p.entity} policy={p} onSave={save} />
            ))}
          </tbody>
        </table>
      ) : null}
      <div className="mt-4 border-t border-slate-200 pt-3">
        <div className="flex items-baseline gap-3">
          <h2 className="text-base font-semibold tracking-tight">Snapshot orphans</h2>
          <button onClick={checkOrphans} className="btn btn-secondary">
            Check orphans
          </button>
          <button onClick={collectOrphans} className="border border-rose-200 bg-white px-3 py-1 text-xs font-medium text-deny hover:bg-rose-50">
            Collect orphans
          </button>
        </div>
        {orphans ? (
          <p className="mt-2 font-ledger text-xs">
            {orphans.count} orphaned snapshots · {orphans.referenced} referenced
          </p>
        ) : null}
        {orphans && orphans.sample.length > 0 ? (
          <ol className="mt-1 font-ledger text-xs text-slate-500">
            {orphans.sample.map((k) => (
              <li key={k}>{k.slice(0, 8)}…</li>
            ))}
          </ol>
        ) : null}
        {collected !== null ? (
          <p className="mt-2 font-ledger text-xs">Deleted {collected} orphaned snapshots</p>
        ) : null}
      </div>
    </section>
  )
}

function PolicyRow({
  policy,
  onSave,
}: {
  policy: Policy
  onSave: (entity: string, days: number) => void
}) {
  const [days, setDays] = useState(policy.retain_days)
  return (
    <tr className="border-t border-neutral-200">
      <td className="px-3 py-1 uppercase">{policy.entity}</td>
      <td className="px-3 py-1">
        <input
          type="number"
          min={0}
          max={3650}
          className="input w-24"
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
        />
      </td>
      <td className="px-3 py-1">
        <button onClick={() => onSave(policy.entity, days)} className="btn-chip">
          Save
        </button>
      </td>
    </tr>
  )
}
