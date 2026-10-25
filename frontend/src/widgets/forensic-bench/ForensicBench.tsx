import { useEffect, useState } from 'react'
import { CheckCircle2, FileDown, Flame, Link2, Radar, Siren, ScanFace, XCircle } from 'lucide-react'
import { onIncidentEvent } from '@/shared/lib'
import { apiFetch } from '@/shared/api'

interface SearchHit {
  id: string
  entry_log_id: string | null
  application_id: string | null
  distance: number
}

type IncidentStatus = 'open' | 'investigating' | 'resolved' | 'closed'

interface IncidentLink {
  id: string
  incident_id: string
  kind: string
  ref_id: string
  note: string
  added_by: string
  added_at: string
}

interface Incident {
  id: string
  site_id: string | null
  title: string
  description: string
  suspect_application_id: string | null
  status: IncidentStatus
  assigned_to: string | null
  resolved_at: string | null
  sla_due_at: string | null
  escalated_at: string | null
  merged_into: string | null
  overdue: boolean
  created_by: string
  created_at: string
}

interface GateHeat {
  gate_id: string
  gate_name: string
  entries: number
  exits: number
}

function apiError(body: unknown, fallback: string): string {
  if (body !== null && typeof body === 'object' && 'error' in body) {
    const err: unknown = body.error
    if (typeof err === 'string' && err.length > 0) return err
  }
  return fallback
}

function parseVector(text: string): number[] | null {
  const parts = text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
  if (parts.length !== 512) return null
  const nums = parts.map(Number)
  if (nums.some((n) => !Number.isFinite(n))) return null
  return nums
}

export default function ForensicBench({ siteId }: { siteId: string | null }) {
  const [vectorText, setVectorText] = useState('')
  const [hits, setHits] = useState<SearchHit[] | null>(null)
  const [incidents, setIncidents] = useState<Incident[] | null>(null)
  const [heat, setHeat] = useState<GateHeat[] | null>(null)
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [notice, setNotice] = useState<string | null>(null)
  const [ok, setOk] = useState<string | null>(null)
  const [links, setLinks] = useState<Record<string, IncidentLink[]>>({})
  const [assignee, setAssignee] = useState<Record<string, string>>({})
  const [linkKind, setLinkKind] = useState<Record<string, string>>({})
  const [linkRef, setLinkRef] = useState<Record<string, string>>({})
  const [linkNote, setLinkNote] = useState<Record<string, string>>({})
  const [mergeInto, setMergeInto] = useState<Record<string, string>>({})
  const [statusTab, setStatusTab] = useState<'all' | IncidentStatus>('all')
  const [mineOnly, setMineOnly] = useState(false)
  const [roster, setRoster] = useState<{ id: string; username: string; role: string }[] | null>(null)
  async function search() {
    setNotice(null)
    setOk(null)
    const embedding = parseVector(vectorText)
    if (!embedding) {
      setNotice('Paste exactly 512 comma-separated finite numbers')
      return
    }
    const res = await apiFetch('/forensics/search', {
      method: 'POST',
      body: JSON.stringify({ embedding, threshold: 0.5, limit: 10 }),
    })
    const body: unknown = await res.json().catch(() => ({}))
    if (!res.ok) {
      setNotice(apiError(body, 'Search failed'))
      return
    }
    setHits(body as SearchHit[])
  }

  function incidentQuery() {
    const params = new URLSearchParams()
    if (statusTab !== 'all') params.set('status', statusTab)
    if (mineOnly) params.set('assignee', 'me')
    const q = params.size > 0 ? `?${params}` : ''
    return `/sites/${siteId}/incidents${q}`
  }

  async function loadIncidents() {
    if (!siteId) return
    const res = await apiFetch(incidentQuery())
    if (res.ok) setIncidents((await res.json()) as Incident[])
  }

  async function loadRoster() {
    const res = await apiFetch('/users/assignable')
    if (res.ok) setRoster((await res.json()) as { id: string; username: string; role: string }[])
  }

  useEffect(() => {
    void loadIncidents()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [siteId, statusTab, mineOnly])

  // Roster changes rarely (provisioning); load once per mount.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    void loadRoster()
  }, [])

  // Live refresh: fellow analysts' mutations arrive on the shared stream.
  // Re-subscribes when the site OR the active filter changes, so filtered
  // views stay filtered on events; manual Refresh is the lag/drop fallback.
  // Query string built inline (not via incidentQuery) so the dep array is
  // exhaustive without resubscribing every render.
  useEffect(
    () =>
      onIncidentEvent((ev) => {
        // Absent site_id = liberal match (older payloads always carry it).
        if (!siteId || (ev.site_id && ev.site_id !== siteId)) return
        const params = new URLSearchParams()
        if (statusTab !== 'all') params.set('status', statusTab)
        if (mineOnly) params.set('assignee', 'me')
        const q = params.size > 0 ? `?${params}` : ''
        void apiFetch(`/sites/${siteId}/incidents${q}`).then(async (res) => {
          if (res.ok) setIncidents((await res.json()) as Incident[])
        })
      }),
    [siteId, statusTab, mineOnly],
  )

  async function loadHeat() {
    if (!siteId) return
    const res = await apiFetch(`/sites/${siteId}/heatmap`)
    if (res.ok) setHeat((await res.json()) as GateHeat[])
  }
  async function fileIncident(e: React.FormEvent) {
    e.preventDefault()
    setNotice(null)
    setOk(null)
    if (!siteId) {
      setNotice('Select a site first')
      return
    }
    const res = await apiFetch(`/sites/${siteId}/incidents`, {
      method: 'POST',
      body: JSON.stringify({ title, description }),
    })
    const body: unknown = await res.json().catch(() => ({}))
    if (!res.ok) {
      setNotice(apiError(body, 'Could not file incident'))
      return
    }
    setTitle('')
    setDescription('')
    setOk('Incident filed')
    loadIncidents()
  }

  const NEXT: Record<IncidentStatus, IncidentStatus[]> = {
    open: ['investigating'],
    investigating: ['resolved'],
    resolved: ['closed'],
    closed: ['investigating'],
  }

  async function transition(id: string, status: IncidentStatus) {
    if (!siteId) return
    setNotice(null)
    const res = await apiFetch(`/sites/${siteId}/incidents/${id}/status`, {
      method: 'POST',
      body: JSON.stringify({ status }),
    })
    if (!res.ok) {
      setNotice(apiError(await res.json().catch(() => ({})), 'Transition rejected'))
      return
    }
    setOk(`Incident → ${status}`)
    loadIncidents()
  }

  async function assign(id: string) {
    if (!siteId) return
    const user_id = (assignee[id] ?? '').trim()
    if (!user_id) {
      setNotice('Pick an assignee first')
      return
    }
    setNotice(null)
    const res = await apiFetch(`/sites/${siteId}/incidents/${id}/assign`, {
      method: 'POST',
      body: JSON.stringify({ user_id }),
    })
    if (!res.ok) {
      setNotice(apiError(await res.json().catch(() => ({})), 'Assign rejected'))
      return
    }
    setOk('Case assigned')
    loadIncidents()
  }

  async function loadLinks(id: string) {
    if (!siteId) return
    const res = await apiFetch(`/sites/${siteId}/incidents/${id}/links`)
    if (res.ok) {
      const rows = (await res.json()) as IncidentLink[]
      setLinks((prev) => ({ ...prev, [id]: rows }))
    }
  }

  async function addLink(id: string) {
    if (!siteId) return
    const kind = linkKind[id] ?? 'note'
    const ref_id = (linkRef[id] ?? '').trim()
    const note = (linkNote[id] ?? '').trim()
    setNotice(null)
    const res = await apiFetch(`/sites/${siteId}/incidents/${id}/links`, {
      method: 'POST',
      body: JSON.stringify({ kind, ref_id, note }),
    })
    if (!res.ok) {
      setNotice(apiError(await res.json().catch(() => ({})), 'Link rejected'))
      return
    }
    setOk('Evidence attached')
    loadLinks(id)
  }


  async function mergeCase(id: string, into: string) {
    setOk(null); setNotice(null)
    if (!into) return
    const res = await apiFetch(`/sites/${siteId}/incidents/${id}/merge`, {
      method: 'POST',
      body: JSON.stringify({ into }),
    })
    if (!res.ok) {
      setNotice(apiError(await res.json().catch(() => ({})), 'Merge refused'))
      return
    }
    setOk('Case merged')
    void loadIncidents()
  }

  async function exportPack(id: string) {
    const res = await apiFetch(`/sites/${siteId}/incidents/${id}/pack`)
    if (!res.ok) {
      setNotice(apiError(await res.json().catch(() => ({})), 'Pack export refused'))
      return
    }
    const blob = await res.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `case-pack-${id.slice(0, 8)}.json`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-1.5 text-lg font-semibold tracking-tight">
        <Radar className="h-4 w-4 text-slate-400" /> Forensic bench
      </h2>
      {notice ? (
        <p role="alert" className="mt-3 flex items-start gap-2 rounded-xl border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-deny">
          <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
          {notice}
        </p>
      ) : null}
      {ok ? (
        <p className="mt-3 flex items-start gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-ok">
          <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
          {ok}
        </p>
      ) : null}
      <div className="mt-3 grid gap-4 md:grid-cols-2">
        <div className="card card-hover p-4">
          <h3 className="flex items-center gap-1.5 text-base font-semibold tracking-tight">
            <ScanFace className="h-4 w-4 text-slate-400" /> Face search
          </h3>
          <label className="mt-2 flex flex-col gap-1 text-sm">
            Suspect embedding (512 floats)
            <textarea
              className="input font-ledger text-xs"
              rows={4}
              value={vectorText}
              onChange={(e) => setVectorText(e.target.value)}
              placeholder="0.11, -0.02, … (512 numbers)"
            />
          </label>
          <button onClick={search} className="btn btn-primary mt-2">
            Search attendees
          </button>
          {hits !== null && hits.length === 0 ? (
            <p className="mt-2 text-sm text-slate-500">No matches within threshold.</p>
          ) : null}
          <ol className="mt-2 divide-y divide-slate-100">
            {(hits ?? []).map((h, rank) => (
              <li key={h.id} className="flex items-center gap-2 py-1.5 font-ledger text-xs transition-colors hover:bg-slate-50/70">
                <span className="w-5 text-right text-slate-400">{rank + 1}</span>
                <span className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5">{h.distance.toFixed(4)}</span>
                <span className="truncate">{h.application_id ?? h.entry_log_id ?? h.id}</span>
              </li>
            ))}
          </ol>
        </div>
        <div className="card card-hover p-4">
          <h3 className="flex items-center gap-1.5 text-base font-semibold tracking-tight">
            <Siren className="h-4 w-4 text-slate-400" /> Incidents
          </h3>
          <form onSubmit={fileIncident} className="mt-2 flex flex-col gap-2">
            <input className="input" placeholder="Title" value={title} onChange={(e) => setTitle(e.target.value)} />
            <input className="input" placeholder="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
            <button type="submit" className="btn btn-primary">File incident</button>
          </form>
          <button onClick={loadIncidents} className="btn btn-secondary mt-2">Refresh incidents</button>
          <div className="mt-2 flex flex-wrap gap-1">
            {(['all', 'open', 'investigating', 'resolved', 'closed'] as const).map((s) => (
              <button
                key={s}
                onClick={() => {
                  setStatusTab(s)
                  setNotice(null)
                }}
                className={`rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition-colors ${statusTab === s ? 'border-navy bg-navy text-white' : 'border-slate-300 text-slate-600 hover:border-slate-400 hover:bg-slate-50'}`}
              >
                {s}
              </button>
            ))}
            <button
              onClick={() => setMineOnly((v) => !v)}
              className={`rounded-full border px-2.5 py-0.5 font-ledger text-[11px] uppercase transition-colors ${mineOnly ? 'border-navy bg-navy text-white' : 'border-slate-300 text-slate-600 hover:border-slate-400 hover:bg-slate-50'}`}
            >
              Mine
            </button>
          </div>
          {(incidents ?? []).length === 0 ? (
            <p className="mt-3 text-sm text-slate-500">No incidents match this view.</p>
          ) : null}
          <ol className="mt-2 space-y-2">
            {(incidents ?? []).map((i) => (
              <li key={i.id} className="card card-hover p-3 text-sm">
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="font-semibold">{i.title}</span>
                  <span className={`pill ${i.status === 'open' ? 'pill-open' : i.status === 'investigating' ? 'pill-active' : i.status === 'resolved' ? 'pill-ok' : 'pill-neutral'}`}>{i.status}</span>
                  {i.overdue ? <span className="pill pill-archived">SLA breached</span> : null}
                  {i.escalated_at ? <span className="pill pill-warn">escalated</span> : null}
                  {i.merged_into ? <span className="pill pill-neutral font-ledger">merged → {i.merged_into.slice(0, 8)}</span> : null}
                  {i.sla_due_at && !i.merged_into ? <span className="font-ledger text-[11px] text-slate-500">SLA {new Date(i.sla_due_at).toLocaleDateString()}</span> : null}
                  {i.assigned_to ? <span className="font-ledger text-xs text-slate-600"> → {i.assigned_to.slice(0, 8)}</span> : null}
                </div>
                {i.description ? <p className="mt-0.5 text-slate-500">{i.description}</p> : null}
                <div className="mt-2 flex flex-wrap gap-1">
                  {i.merged_into ? null : (NEXT[i.status] ?? []).map((s) => (
                    <button key={s} onClick={() => transition(i.id, s)} className="btn-chip">
                      → {s}
                    </button>
                  ))}
                  <button onClick={() => loadLinks(i.id)} className="btn-chip">
                    <Link2 className="h-3 w-3" /> Links ({(links[i.id] ?? []).length})
                  </button>
                  <button onClick={() => exportPack(i.id)} className="btn-chip">
                    <FileDown className="h-3 w-3" /> Export pack
                  </button>
                </div>
                {i.merged_into ? null : (
                  <div className="mt-1.5 flex flex-wrap items-center gap-1">
                    <select
                      aria-label={`Merge ${i.title} into`}
                      className="input !w-auto !px-2 !py-0.5 font-ledger !text-xs"
                      value={mergeInto[i.id] ?? ''}
                      onChange={(e) => setMergeInto((p) => ({ ...p, [i.id]: e.target.value }))}
                    >
                      <option value="">merge into…</option>
                      {(incidents ?? []).filter((o) => o.id !== i.id && !o.merged_into).map((o) => (
                        <option key={o.id} value={o.id}>{o.title} ({o.status})</option>
                      ))}
                    </select>
                    <button onClick={() => mergeCase(i.id, mergeInto[i.id] ?? '')} className="btn-chip">
                      Merge
                    </button>
                  </div>
                )}
                <div className="mt-1.5 flex flex-wrap gap-1">
                  <select
                    className="input !w-auto !px-2 !py-0.5 font-ledger !text-xs"
                    value={assignee[i.id] ?? ''}
                    onChange={(e) => setAssignee((p) => ({ ...p, [i.id]: e.target.value }))}
                    onFocus={() => {
                      if (roster === null) void loadRoster()
                    }}
                  >
                    <option value="">assignee…</option>
                    {(roster ?? []).map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.username} ({u.role})
                      </option>
                    ))}
                  </select>
                  <button onClick={() => assign(i.id)} className="btn-chip-solid">Assign</button>
                </div>
                {(links[i.id] ?? []).length > 0 ? (
                  <ol className="mt-1.5 space-y-0.5 rounded-lg border border-slate-200 bg-slate-50/70 p-2 font-ledger text-xs">
                    {(links[i.id] ?? []).map((l) => (
                      <li key={l.id} className="flex gap-2">
                        <span className="rounded bg-white px-1 font-medium text-slate-600">{l.kind}</span>
                        <span className="truncate">{l.ref_id}</span>
                        {l.note ? <span className="truncate text-slate-500">{l.note}</span> : null}
                      </li>
                    ))}
                  </ol>
                ) : null}
                <div className="mt-1.5 flex flex-wrap gap-1">
                  <select
                    className="input !w-auto !px-2 !py-0.5 font-ledger !text-xs"
                    value={linkKind[i.id] ?? 'note'}
                    onChange={(e) => setLinkKind((p) => ({ ...p, [i.id]: e.target.value }))}
                  >
                    <option value="note">note</option>
                    <option value="entry">entry</option>
                    <option value="embedding">embedding</option>
                    <option value="snapshot">snapshot</option>
                  </select>
                  <input
                    className="input !w-32 !px-2 !py-0.5 font-ledger !text-xs"
                    placeholder="ref id / key"
                    value={linkRef[i.id] ?? ''}
                    onChange={(e) => setLinkRef((p) => ({ ...p, [i.id]: e.target.value }))}
                  />
                  <input
                    className="input !w-28 !px-2 !py-0.5 font-ledger !text-xs"
                    placeholder="note"
                    value={linkNote[i.id] ?? ''}
                    onChange={(e) => setLinkNote((p) => ({ ...p, [i.id]: e.target.value }))}
                  />
                  <button onClick={() => addLink(i.id)} className="btn-chip">Attach</button>
                </div>
              </li>
            ))}
          </ol>
        </div>
      </div>
      <div className="card card-hover mt-4 p-4">
        <div className="flex items-center gap-3">
          <h3 className="flex items-center gap-1.5 text-base font-semibold tracking-tight">
            <Flame className="h-4 w-4 text-slate-400" /> Gate heat (24h)
          </h3>
          <button onClick={loadHeat} className="btn btn-secondary">Load heatmap</button>
        </div>
        {(heat ?? []).length > 0 ? (
          <table className="mt-2 w-full font-ledger text-xs">
            <thead>
              <tr className="text-left uppercase">
                <th>Gate</th>
                <th>In</th>
                <th>Out</th>
                <th>Load</th>
              </tr>
            </thead>
            <tbody>
              {(heat ?? []).map((g) => {
                const total = g.entries + g.exits
                const max = Math.max(...(heat ?? []).map((h) => h.entries + h.exits), 1)
                return (
                  <tr key={g.gate_id} className="border-t border-slate-100 transition-colors hover:bg-slate-50/70">
                    <td className="py-1.5 uppercase">{g.gate_name}</td>
                    <td className="tabular-nums">{g.entries}</td>
                    <td className="tabular-nums">{g.exits}</td>
                    <td className="w-40">
                      <span
                        className="block h-2.5 rounded-full bg-signal transition-all"
                        style={{ width: `${Math.max(4, Math.round((total / max) * 140))}px`, opacity: total / max }}
                      />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        ) : (
          <p className="mt-2 text-sm text-slate-500">No heat loaded yet — pull the last 24 hours.</p>
        )}
      </div>
    </section>
  )
}
