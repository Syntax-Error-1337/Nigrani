import { useEffect, useState } from 'react'
import { onIncidentEvent } from './events'
import { apiFetch } from './session'

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
  const [statusTab, setStatusTab] = useState<'all' | IncidentStatus>('all')
  const [mineOnly, setMineOnly] = useState(false)
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

  // Tab/filter changes reload immediately (tab clicks are not WS events).
  useEffect(() => {
    void loadIncidents()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [siteId, statusTab, mineOnly])

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
      setNotice('Paste an assignee user id first')
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


  return (
    <section className="mt-8">
      <h2 className="font-display text-2xl uppercase">Forensic bench</h2>
      {notice ? (
        <p role="alert" className="mt-3 border border-deny bg-red-50 px-3 py-2 text-sm text-deny">
          {notice}
        </p>
      ) : null}
      {ok ? (
        <p className="mt-3 border border-ok bg-green-50 px-3 py-2 text-sm text-ok">{ok}</p>
      ) : null}
      <div className="mt-3 grid gap-4 md:grid-cols-2">
        <div className="border-2 border-ink bg-white p-4">
          <h3 className="font-display text-lg uppercase">Face search</h3>
          <label className="mt-2 flex flex-col gap-1 text-sm">
            Suspect embedding (512 floats)
            <textarea
              className="border border-ink px-3 py-2 font-ledger text-xs"
              rows={4}
              value={vectorText}
              onChange={(e) => setVectorText(e.target.value)}
              placeholder="0.11, -0.02, … (512 numbers)"
            />
          </label>
          <button onClick={search} className="mt-2 bg-ink px-4 py-2 text-sm uppercase text-paper">
            Search attendees
          </button>
          {hits !== null && hits.length === 0 ? (
            <p className="mt-2 text-sm">No matches within threshold.</p>
          ) : null}
          <ol className="mt-2 divide-y divide-neutral-200">
            {(hits ?? []).map((h) => (
              <li key={h.id} className="flex items-baseline gap-2 py-1 font-ledger text-xs">
                <span>{h.distance.toFixed(4)}</span>
                <span className="truncate">{h.application_id ?? h.entry_log_id ?? h.id}</span>
              </li>
            ))}
          </ol>
        </div>
        <div className="border-2 border-ink bg-white p-4">
          <h3 className="font-display text-lg uppercase">Incidents</h3>
          <form onSubmit={fileIncident} className="mt-2 flex flex-col gap-2">
            <input
              className="border border-ink px-3 py-2 text-sm"
              placeholder="Title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
            <input
              className="border border-ink px-3 py-2 text-sm"
              placeholder="Description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
            <button type="submit" className="bg-ink px-4 py-2 text-sm uppercase text-paper">
              File incident
            </button>
          </form>
          <button onClick={loadIncidents} className="mt-2 border border-ink px-3 py-1 font-ledger text-xs uppercase">
            Refresh incidents
          </button>
          <div className="mt-2 flex flex-wrap gap-1">
            {(['all', 'open', 'investigating', 'resolved', 'closed'] as const).map((s) => (
              <button
                key={s}
                onClick={() => {
                  setStatusTab(s)
                  setNotice(null)
                }}
                className={`border px-2 py-0.5 font-ledger text-[11px] uppercase ${statusTab === s ? 'border-ink bg-ink text-paper' : 'border-ink'}`}
              >
                {s}
              </button>
            ))}
            <button
              onClick={() => setMineOnly((v) => !v)}
              className={`border px-2 py-0.5 font-ledger text-[11px] uppercase ${mineOnly ? 'border-ink bg-ink text-paper' : 'border-ink'}`}
            >
              Mine
            </button>
          </div>
          <ol className="mt-2 divide-y divide-neutral-200">
            {(incidents ?? []).map((i) => (
              <li key={i.id} className="py-2 text-sm">
                <span className="font-display uppercase">{i.title}</span>{' '}
                <span className="border border-ink px-1 font-ledger text-[11px] uppercase">{i.status}</span>
                {i.assigned_to ? <span className="font-ledger text-xs"> → {i.assigned_to.slice(0, 8)}</span> : null}
                {i.description ? <span className="text-neutral-500"> — {i.description}</span> : null}
                <div className="mt-1 flex flex-wrap gap-1">
                  {(NEXT[i.status] ?? []).map((s) => (
                    <button key={s} onClick={() => transition(i.id, s)} className="border border-ink px-2 py-0.5 font-ledger text-[11px] uppercase">
                      → {s}
                    </button>
                  ))}
                  <button onClick={() => loadLinks(i.id)} className="border border-ink px-2 py-0.5 font-ledger text-[11px] uppercase">
                    Links ({(links[i.id] ?? []).length})
                  </button>
                </div>
                <div className="mt-1 flex flex-wrap gap-1">
                  <input
                    className="border border-ink px-2 py-0.5 font-ledger text-xs"
                    placeholder="assignee user id"
                    value={assignee[i.id] ?? ''}
                    onChange={(e) => setAssignee((p) => ({ ...p, [i.id]: e.target.value }))}
                  />
                  <button onClick={() => assign(i.id)} className="bg-ink px-2 py-0.5 font-ledger text-[11px] uppercase text-paper">
                    Assign
                  </button>
                </div>
                {(links[i.id] ?? []).length > 0 ? (
                  <ol className="mt-1 font-ledger text-xs">
                    {(links[i.id] ?? []).map((l) => (
                      <li key={l.id}>[{l.kind}] {l.ref_id} {l.note}</li>
                    ))}
                  </ol>
                ) : null}
                <div className="mt-1 flex flex-wrap gap-1">
                  <select
                    className="border border-ink px-1 py-0.5 font-ledger text-xs"
                    value={linkKind[i.id] ?? 'note'}
                    onChange={(e) => setLinkKind((p) => ({ ...p, [i.id]: e.target.value }))}
                  >
                    <option value="note">note</option>
                    <option value="entry">entry</option>
                    <option value="embedding">embedding</option>
                    <option value="snapshot">snapshot</option>
                  </select>
                  <input
                    className="border border-ink px-2 py-0.5 font-ledger text-xs"
                    placeholder="ref id / key"
                    value={linkRef[i.id] ?? ''}
                    onChange={(e) => setLinkRef((p) => ({ ...p, [i.id]: e.target.value }))}
                  />
                  <input
                    className="border border-ink px-2 py-0.5 font-ledger text-xs"
                    placeholder="note"
                    value={linkNote[i.id] ?? ''}
                    onChange={(e) => setLinkNote((p) => ({ ...p, [i.id]: e.target.value }))}
                  />
                  <button onClick={() => addLink(i.id)} className="border border-ink px-2 py-0.5 font-ledger text-[11px] uppercase">
                    Attach
                  </button>
                </div>
              </li>
            ))}
          </ol>
        </div>
      </div>
      <div className="mt-4 border-2 border-ink bg-white p-4">
        <div className="flex items-baseline gap-3">
          <h3 className="font-display text-lg uppercase">Gate heat (24h)</h3>
          <button onClick={loadHeat} className="border border-ink px-3 py-1 font-ledger text-xs uppercase">
            Load heatmap
          </button>
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
                return (
                  <tr key={g.gate_id} className="border-t border-neutral-200">
                    <td className="py-1 uppercase">{g.gate_name}</td>
                    <td>{g.entries}</td>
                    <td>{g.exits}</td>
                    <td>
                      <span
                        className="inline-block h-3 bg-signal"
                        style={{ width: `${Math.min(100, total * 10)}px` }}
                      />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        ) : (
          <p className="mt-2 text-sm">No heat loaded yet.</p>
        )}
      </div>
    </section>
  )
}
