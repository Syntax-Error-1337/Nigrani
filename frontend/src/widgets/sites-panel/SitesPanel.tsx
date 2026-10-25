import { useState } from 'react'
import { Archive, ArchiveRestore, MapPin, Plus, ScanLine, XCircle } from 'lucide-react'
import { useGates, type Site } from '@/entities/site'
import { apiFetch } from '@/shared/api'

/// Sites & gates management (s-S3): topology tables, selection, duty
/// assignment, and create/archive forms — extracted from the Dashboard
/// monolith. Selection lives in the Dashboard (site-scoped panels read it).
interface SitesPanelProps {
  sites: Site[]
  sitesLoading: boolean
  sitesError: boolean
  refetchSites: () => void
  siteId: string | null
  gateId: string | null
  onSelectSite: (id: string) => void
  onSelectGate: (id: string | null) => void
  canWrite: boolean
}

export default function SitesPanel({
  sites,
  sitesLoading,
  sitesError,
  refetchSites,
  siteId,
  gateId,
  onSelectSite,
  onSelectGate,
  canWrite,
}: SitesPanelProps) {
  const activeSiteId = siteId ?? sites[0]?.id ?? null
  const [siteSearch, setSiteSearch] = useState('')
  const [gateSearch, setGateSearch] = useState('')
  const [showArchivedSites, setShowArchivedSites] = useState(false)
  const [showArchivedGates, setShowArchivedGates] = useState(false)
  const [newSite, setNewSite] = useState({ name: '', location: '' })
  const [newGate, setNewGate] = useState({ name: '', direction: 'entry' })
  const [gateFormSite, setGateFormSite] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [dutyCandidates, setDutyCandidates] = useState<
    { id: string; username: string; role: string }[] | null
  >(null)

  // Duty roster for the assignment dropdowns (write roles only).
  if (canWrite && dutyCandidates === null) {
    void apiFetch('/users/assignable?perm=entries:write').then(async (res) => {
      if (res.ok) setDutyCandidates((await res.json()) as typeof dutyCandidates)
    })
  }
  const gatesQuery = useGates(activeSiteId, gateSearch, showArchivedGates)

  const firstError = (body: unknown, fallback: string): string => {
    if (body !== null && typeof body === 'object' && 'error' in body) {
      const err: unknown = body.error
      if (typeof err === 'string' && err.length > 0) return err
    }
    return fallback
  }

  async function assignDuty(gate: { id: string; site_id: string }, userId: string | null) {
    setNotice(null)
    const res = await apiFetch(`/sites/${gate.site_id}/gates/${gate.id}/duty`, {
      method: 'POST',
      body: JSON.stringify({ user_id: userId }),
    })
    if (!res.ok) {
      setNotice(firstError(await res.json().catch(() => ({})), 'Could not set duty officer'))
      return
    }
    gatesQuery.refetch()
  }

  async function createSite(e: React.FormEvent) {
    e.preventDefault()
    setNotice(null)
    const res = await apiFetch('/sites', {
      method: 'POST',
      body: JSON.stringify({ name: newSite.name, location: newSite.location }),
    })
    if (!res.ok) {
      setNotice(firstError(await res.json().catch(() => ({})), 'Could not create site'))
      return
    }
    setNewSite({ name: '', location: '' })
    refetchSites()
  }

  async function createGate(e: React.FormEvent) {
    e.preventDefault()
    const targetSite = gateFormSite ?? activeSiteId
    if (!targetSite) return
    setNotice(null)
    const res = await apiFetch(`/sites/${targetSite}/gates`, {
      method: 'POST',
      body: JSON.stringify({ name: newGate.name, direction: newGate.direction }),
    })
    if (!res.ok) {
      setNotice(firstError(await res.json().catch(() => ({})), 'Could not create gate'))
      return
    }
    setNewGate({ name: '', direction: 'entry' })
    onSelectSite(targetSite)
    setGateFormSite(null)
    gatesQuery.refetch()
  }

  async function flipSite(site: { id: string; archived_at: string | null }) {
    setNotice(null)
    const action = site.archived_at ? 'restore' : 'archive'
    const res = await apiFetch(`/sites/${site.id}/archive/${action}`, { method: 'POST' })
    if (!res.ok) {
      setNotice(firstError(await res.json().catch(() => ({})), `Could not ${action} site`))
      return
    }
    refetchSites()
  }

  async function flipGate(gate: { id: string; site_id: string; archived_at: string | null }) {
    setNotice(null)
    const action = gate.archived_at ? 'restore' : 'archive'
    const res = await apiFetch(`/sites/${gate.site_id}/gates/${gate.id}/archive/${action}`, {
      method: 'POST',
    })
    if (!res.ok) {
      setNotice(firstError(await res.json().catch(() => ({})), `Could not ${action} gate`))
      return
    }
    gatesQuery.refetch()
  }

  const statusPill = (archived: boolean) =>
    archived ? (
      <span className="inline-flex items-center gap-1 rounded-full border border-rose-200 bg-rose-50 px-2 py-0.5 text-[10px] font-medium text-deny">
        <Archive className="h-2.5 w-2.5" /> Archived
      </span>
    ) : (
      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-[10px] font-medium text-ok">
        <span className="h-1.5 w-1.5 rounded-full bg-ok" /> Active
      </span>
    )

  return (
    <>
      {notice ? (
        <p role="alert" className="flex items-start gap-2 rounded-xl border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-deny">
          <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
          {notice}
        </p>
      ) : null}

      {/* --- Sites --- */}
      <section className="mt-6">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold tracking-tight">Protest sites</h2>
          <input
            className="input ml-auto w-56"
            placeholder="Search sites…"
            value={siteSearch}
            onChange={(e) => setSiteSearch(e.target.value)}
          />
          {canWrite ? (
            <button
              onClick={() => setShowArchivedSites((v) => !v)}
              className="btn btn-secondary"
            >
              {showArchivedSites ? 'Hide archived' : 'Show archived'}
            </button>
          ) : null}
        </div>
        {sitesLoading ? (
          <div className="mt-3 rounded-xl border border-slate-200 bg-white p-2 shadow-sm" aria-hidden="true">
            <span className="skeleton mb-2 h-10 w-full opacity-70" />
            <span className="skeleton mb-2 h-10 w-full opacity-50" />
            <span className="skeleton h-10 w-full opacity-40" />
          </div>
        ) : null}
        {sitesError ? (
          <p role="alert" className="mt-2 text-sm text-deny">
            Sites would not load. Check the API connection.
          </p>
        ) : null}
        {sites.length === 0 && !sitesLoading ? (
          <p className="mt-8 text-center text-sm text-slate-500">
            <MapPin className="mx-auto h-5 w-5" />
            <span className="mt-1 block">No protest sites yet{canWrite ? ' — add the first one below.' : '.'}</span>
          </p>
        ) : null}
        {sites.length > 0 ? (
          <div className="mt-3 overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
            <table className="w-full min-w-[560px] table-fixed text-sm">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50/60 text-left text-xs text-slate-500">
                  <th className="w-[40%] px-4 py-2.5 font-medium">Site</th>
                  <th className="hidden w-[22%] px-4 py-2.5 font-medium sm:table-cell">Location</th>
                  <th className="hidden w-[12%] px-4 py-2.5 font-medium md:table-cell">Created</th>
                  <th className="w-[12%] px-4 py-2.5 font-medium">Status</th>
                  <th className="w-[14%] px-4 py-2.5"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {sites.map((site) => (
                  <tr
                    key={site.id}
                    onClick={() => onSelectSite(site.id)}
                    className={`cursor-pointer border-b border-slate-100 transition-colors last:border-0 ${
                      activeSiteId === site.id ? 'bg-saffron-mist/60' : 'hover:bg-slate-50'
                    } ${site.archived_at ? 'opacity-60' : ''}`}
                  >
                    <td className="max-w-0 px-4 py-2.5">
                      <span className="flex items-center gap-2 truncate font-medium" title={site.name}>
                        <MapPin className={`h-3.5 w-3.5 shrink-0 ${activeSiteId === site.id ? 'text-saffron-ink' : 'text-slate-400'}`} />
                        {site.name}
                      </span>
                    </td>
                    <td className="hidden max-w-40 truncate px-4 py-2.5 text-slate-500 sm:table-cell">
                      {site.location || '—'}
                    </td>
                    <td className="hidden whitespace-nowrap px-4 py-2.5 font-ledger text-xs text-slate-500 md:table-cell">
                      {new Date(site.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-2.5">{statusPill(site.archived_at !== null)}</td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-right">
                      {canWrite ? (
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            void flipSite(site)
                          }}
                          className="btn-chip"
                        >
                          {site.archived_at ? <ArchiveRestore className="h-3 w-3" /> : <Archive className="h-3 w-3" />}
                          {site.archived_at ? 'Restore' : 'Archive'}
                        </button>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        {canWrite ? (
          <form onSubmit={createSite} className="mt-4 flex flex-wrap items-end gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <label className="flex flex-col gap-1 text-sm">
              New site
              <input
                className="input w-56"
                value={newSite.name}
                onChange={(e) => setNewSite({ ...newSite, name: e.target.value })}
                placeholder="e.g. Ramlila Maidan"
              />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              Location
              <input
                className="input w-40"
                value={newSite.location}
                onChange={(e) => setNewSite({ ...newSite, location: e.target.value })}
                placeholder="City"
              />
            </label>
            <button type="submit" className="btn btn-primary">
              <Plus className="h-3.5 w-3.5" /> Add site
            </button>
          </form>
        ) : null}
      </section>

      {/* --- Gates --- */}
      <section className="mt-10">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold tracking-tight">Gates</h2>
          {activeSiteId !== null ? (
            <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-500">
              {(gatesQuery.data ?? []).length} at selected site
            </span>
          ) : null}
          <input
            className="input ml-auto w-56"
            placeholder="Search gates…"
            value={gateSearch}
            onChange={(e) => setGateSearch(e.target.value)}
          />
          {canWrite ? (
            <button
              onClick={() => setShowArchivedGates((v) => !v)}
              className="btn btn-secondary"
            >
              {showArchivedGates ? 'Hide archived' : 'Show archived'}
            </button>
          ) : null}
        </div>
        {activeSiteId === null ? (
          <p className="mt-2 text-sm text-slate-500">Select a site above to see its gates.</p>
        ) : gatesQuery.isLoading ? (
          <div className="mt-3 rounded-xl border border-slate-200 bg-white p-2 shadow-sm" aria-hidden="true">
            <span className="skeleton mb-2 h-10 w-full opacity-70" />
            <span className="skeleton mb-2 h-10 w-full opacity-50" />
            <span className="skeleton h-10 w-full opacity-40" />
          </div>
        ) : gatesQuery.isError ? (
          <p className="mt-2 text-sm text-deny">Gates would not load.</p>
        ) : (gatesQuery.data ?? []).length === 0 ? (
          <p className="mt-2 text-sm text-slate-500">No gates posted at this site yet.</p>
        ) : (
          <div className="mt-3 overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
            <table className="w-full min-w-[560px] table-fixed text-sm">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50/60 text-left text-xs text-slate-500">
                  <th className="w-[34%] px-4 py-2.5 font-medium">Gate</th>
                  <th className="w-[12%] px-4 py-2.5 font-medium">Direction</th>
                  <th className="w-[16%] px-4 py-2.5 font-medium">Duty officer</th>
                  <th className="hidden w-[12%] px-4 py-2.5 font-medium sm:table-cell">Created</th>
                  <th className="w-[12%] px-4 py-2.5 font-medium">Status</th>
                  <th className="w-[14%] px-4 py-2.5"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {(gatesQuery.data ?? []).map((gate) => (
                  <tr
                    key={gate.id}
                    onClick={() => onSelectGate(gate.id)}
                    className={`cursor-pointer border-b border-slate-100 transition-colors last:border-0 ${
                      gateId === gate.id ? 'bg-saffron-mist/60' : 'hover:bg-slate-50'
                    } ${gate.archived_at ? 'opacity-60' : ''}`}
                  >
                    <td className="px-4 py-2.5">
                      <span className="flex items-center gap-2 font-medium">
                        <ScanLine className={`h-3.5 w-3.5 shrink-0 ${gateId === gate.id ? 'text-saffron-ink' : 'text-slate-400'}`} />
                        {gate.name}
                        {gateId === gate.id ? (
                          <span className="text-xs font-medium text-signal">selected</span>
                        ) : null}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-slate-500 first-letter:uppercase">{gate.direction}</td>
                    <td
                      className="px-4 py-2.5"
                      onClick={canWrite ? (e) => e.stopPropagation() : undefined}
                    >
                      {canWrite ? (
                        <select
                          aria-label={`Duty officer at ${gate.name}`}
                          className="input w-full max-w-40 !px-1 !py-0.5 !text-xs"
                          value={gate.duty_officer ?? ''}
                          onChange={(e) => void assignDuty(gate, e.target.value || null)}
                        >
                          <option value="">Unassigned</option>
                          {(dutyCandidates ?? []).map((c) => (
                            <option key={c.id} value={c.id}>
                              {c.username} ({c.role})
                            </option>
                          ))}
                        </select>
                      ) : (
                        <span className="text-slate-500">{gate.duty_username ?? '—'}</span>
                      )}
                    </td>
                    <td className="hidden whitespace-nowrap px-4 py-2.5 font-ledger text-xs text-slate-500 sm:table-cell">
                      {new Date(gate.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-2.5">{statusPill(gate.archived_at !== null)}</td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-right">
                      {canWrite ? (
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            void flipGate(gate)
                          }}
                          className="btn-chip"
                        >
                          {gate.archived_at ? <ArchiveRestore className="h-3 w-3" /> : <Archive className="h-3 w-3" />}
                          {gate.archived_at ? 'Restore' : 'Archive'}
                        </button>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {canWrite && sites.length > 0 ? (
          <form onSubmit={createGate} className="mt-4 flex flex-wrap items-end gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <label className="flex flex-col gap-1 text-sm">
              Site
              <select
                className="input w-56"
                value={gateFormSite ?? activeSiteId ?? ''}
                onChange={(e) => setGateFormSite(e.target.value || null)}
              >
                {sites.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-sm">
              New gate
              <input
                className="input w-40"
                value={newGate.name}
                onChange={(e) => setNewGate({ ...newGate, name: e.target.value })}
                placeholder="e.g. North A"
              />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              Direction
              <select
                className="input w-28"
                value={newGate.direction}
                onChange={(e) => setNewGate({ ...newGate, direction: e.target.value })}
              >
                <option value="entry">Entry</option>
                <option value="exit">Exit</option>
                <option value="both">Both</option>
              </select>
            </label>
            <button type="submit" className="btn btn-primary">
              <Plus className="h-3.5 w-3.5" /> Post gate
            </button>
          </form>
        ) : null}
      </section>
    </>
  )
}
