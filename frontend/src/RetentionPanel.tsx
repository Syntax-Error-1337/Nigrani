import { useState } from 'react'
import { apiFetch } from './session'

interface Policy {
  entity: string
  retain_days: number
}

export default function RetentionPanel() {
  const [policies, setPolicies] = useState<Policy[] | null>(null)
  const [report, setReport] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [orphans, setOrphans] = useState<{ count: number; referenced: number; sample: string[] } | null>(null)
  const [collected, setCollected] = useState<number | null>(null)
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
        setReport(`Purged — ${parts.join(', ')}`)
        return
      }
    }
    setReport('Purge ran')
  }

  async function checkOrphans() {
    setNotice(null)
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
        <h2 className="font-display text-2xl uppercase">Retention</h2>
        <button onClick={load} className="border border-ink px-3 py-1 font-ledger text-xs uppercase">
          Load policies
        </button>
        <button onClick={purge} className="border border-deny px-3 py-1 font-ledger text-xs uppercase text-deny">
          Run purge
        </button>
      </div>
      {notice ? <p className="mt-2 text-sm text-deny">{notice}</p> : null}
      {report ? <p className="mt-2 font-ledger text-xs">{report}</p> : null}
      {(policies ?? []).length > 0 ? (
        <table className="mt-2 w-full border-2 border-ink bg-white font-ledger text-xs">
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
      <div className="mt-4 border-t-2 border-ink pt-3">
        <div className="flex items-baseline gap-3">
          <h3 className="font-display text-lg uppercase">Snapshot orphans</h3>
          <button onClick={checkOrphans} className="border border-ink px-3 py-1 font-ledger text-xs uppercase">
            Check orphans
          </button>
          <button onClick={collectOrphans} className="border border-deny px-3 py-1 font-ledger text-xs uppercase text-deny">
            Collect orphans
          </button>
        </div>
        {orphans ? (
          <p className="mt-2 font-ledger text-xs">
            {orphans.count} orphaned snapshots · {orphans.referenced} referenced
          </p>
        ) : null}
        {orphans && orphans.sample.length > 0 ? (
          <ol className="mt-1 font-ledger text-xs text-neutral-500">
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
          className="w-24 border border-ink px-2 py-1"
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
        />
      </td>
      <td className="px-3 py-1">
        <button onClick={() => onSave(policy.entity, days)} className="border border-ink px-2 py-1 uppercase">
          Save
        </button>
      </td>
    </tr>
  )
}
