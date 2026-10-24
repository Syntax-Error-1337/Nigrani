import { useEffect, useState } from 'react'
import { useDebounced } from '@/shared/lib'
import AuditTrail from '@/widgets/audit-trail'
import DutyPanel from '@/widgets/duty-panel'
import ForensicBench from '@/widgets/forensic-bench'
import Kiosk from '@/widgets/kiosk'
import OperatorsPanel, { PasswordDialog } from '@/widgets/operators-panel'
import RetentionPanel from '@/widgets/retention-panel'
import ReviewDesk from '@/widgets/review-desk'
import TrendsSurge from '@/widgets/trends-surge'
import { useGates, useSites, useStats } from '@/entities/site'
import { apiFetch } from '@/shared/api'
import { useSession, type Role } from '@/shared/session'

const ROLE_PANELS: Record<Role, { heading: string; brief: string }> = {
  SuperAdmin: {
    heading: 'System ledger',
    brief: 'Sites, gates, and accounts. Create protest sites and their entry gates here.',
  },
  SiteCommander: {
    heading: 'Site command',
    brief: 'Your protest site at a glance — gates, directions, and throughput posts.',
  },
  GateOperator: {
    heading: 'Gate kiosk',
    brief: 'Verify arrivals against the gate roster. Select your post to begin screening.',
  },
  VerificationOfficer: {
    heading: 'Press review desk',
    brief: 'Media access requests land here for inspection and approval.',
  },
  ForensicAnalyst: {
    heading: 'Forensic bench',
    brief: 'Similarity search over gate captures, incident log, and gate heatmap.',
  },
}

export default function Dashboard() {
  const user = useSession((s) => s.user)
  const logout = useSession((s) => s.logout)
  const [siteSearch, setSiteSearch] = useState('')
  const [gateSearch, setGateSearch] = useState('')
  const [showArchivedSites, setShowArchivedSites] = useState(false)
  const [showArchivedGates, setShowArchivedGates] = useState(false)

  function setTextSize(size: 'sm' | 'md' | 'lg') {
    // GIGW pattern: user-controlled text scale on the root element.
    const scale = size === 'sm' ? '87.5%' : size === 'lg' ? '112.5%' : '100%'
    document.documentElement.style.fontSize = scale
  }
  const sitesQuery = useSites(useDebounced(siteSearch), showArchivedSites)
  const stats = useStats()
  const [siteId, setSiteId] = useState<string | null>(null)
  const [gateId, setGateId] = useState<string | null>(null)
  const [newSite, setNewSite] = useState({ name: '', location: '' })
  const [newGate, setNewGate] = useState({ name: '', direction: 'entry' })
  const [gateFormSite, setGateFormSite] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [dutyCandidates, setDutyCandidates] = useState<{ id: string; username: string; role: string }[] | null>(
    null,
  )

  const canWritePre = user !== null && (user.role === 'SuperAdmin' || user.role === 'SiteCommander')
  useEffect(() => {
    if (!canWritePre) return
    let live = true
    void apiFetch('/users/assignable?perm=entries:write').then(async (res) => {
      if (res.ok && live) setDutyCandidates((await res.json()) as typeof dutyCandidates)
    })
    return () => {
      live = false
    }
  }, [canWritePre])

  // The gates table (and everything scoped to it) follows the EFFECTIVE
  // site — explicit selection, else the first site. Hook must stay above
  // the `if (!user)` return.
  const gatesQuery = useGates(siteId ?? sitesQuery.data?.[0]?.id ?? null, useDebounced(gateSearch), showArchivedGates)

  if (!user) return null
  const panel = ROLE_PANELS[user.role]
  const canWrite = user.role === 'SuperAdmin' || user.role === 'SiteCommander'
  const sites = sitesQuery.data ?? []
  const activeSiteId = siteId ?? sites[0]?.id ?? null

  async function assignDuty(gate: { id: string; site_id: string }, userId: string | null) {
    setNotice(null)
    const res = await apiFetch(`/sites/${gate.site_id}/gates/${gate.id}/duty`, {
      method: 'POST',
      body: JSON.stringify({ user_id: userId }),
    })
    if (!res.ok) {
      const body: unknown = await res.json().catch(() => ({}))
      const err =
        body !== null && typeof body === 'object' && 'error' in body ? body.error : null
      setNotice(typeof err === 'string' && err.length > 0 ? err : 'Could not set duty officer')
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
      const body: unknown = await res.json().catch(() => ({}))
      const err =
        body !== null && typeof body === 'object' && 'error' in body ? body.error : null
      setNotice(typeof err === 'string' && err.length > 0 ? err : 'Could not create site')
      return
    }
    setNewSite({ name: '', location: '' })
    sitesQuery.refetch()
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
      const body: unknown = await res.json().catch(() => ({}))
      const err =
        body !== null && typeof body === 'object' && 'error' in body ? body.error : null
      setNotice(typeof err === 'string' && err.length > 0 ? err : 'Could not create gate')
      return
    }
    setNewGate({ name: '', direction: 'entry' })
    // Keep the form targeting the same site: scope the table to it so the
    // new gate is visible immediately.
    setSiteId(targetSite)
    setGateFormSite(null)
    gatesQuery.refetch()
  }

  async function flipSite(site: { id: string; archived_at: string | null }) {
    setNotice(null)
    const action = site.archived_at ? 'restore' : 'archive'
    const res = await apiFetch(`/sites/${site.id}/archive/${action}`, { method: 'POST' })
    if (!res.ok) {
      const body: unknown = await res.json().catch(() => ({}))
      const err =
        body !== null && typeof body === 'object' && 'error' in body ? body.error : null
      setNotice(typeof err === 'string' && err.length > 0 ? err : `Could not ${action} site`)
      return
    }
    sitesQuery.refetch()
  }

  async function flipGate(gate: { id: string; site_id: string; archived_at: string | null }) {
    setNotice(null)
    const action = gate.archived_at ? 'restore' : 'archive'
    const res = await apiFetch(`/sites/${gate.site_id}/gates/${gate.id}/archive/${action}`, {
      method: 'POST',
    })
    if (!res.ok) {
      const body: unknown = await res.json().catch(() => ({}))
      const err =
        body !== null && typeof body === 'object' && 'error' in body ? body.error : null
      setNotice(typeof err === 'string' && err.length > 0 ? err : `Could not ${action} gate`)
      return
    }
    gatesQuery.refetch()
  }

  return (
    <main id="main-content" className="min-h-screen bg-paper">
      <header className="sticky top-0 z-10 bg-navy text-white shadow-sm">
        <div className="tricolor-strip h-1 w-full" />
        <div className="flex items-center justify-between px-6 py-3">
          <div className="flex items-center gap-5">
            <div className="flex items-baseline gap-2 text-sm font-semibold tracking-tight">
              <span className="inline-block h-2.5 w-2.5 rounded-full bg-saffron" />
              Nigrani
              <span className="text-xs font-normal text-white/60">सेंटिनेल-गार्ड</span>
            </div>
            <div className="h-5 w-px bg-white/10" />
            <h1 className="text-sm font-medium text-white/80">{panel.heading}</h1>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1 font-ledger text-xs" role="group" aria-label="Text size">
              <button onClick={() => setTextSize('sm')} className="px-1.5 py-0.5 hover:bg-white/10" aria-label="Smaller text">A−</button>
              <button onClick={() => setTextSize('md')} className="px-1.5 py-0.5 hover:bg-white/10" aria-label="Normal text">A</button>
              <button onClick={() => setTextSize('lg')} className="px-1.5 py-0.5 hover:bg-white/10" aria-label="Larger text">A+</button>
            </div>
            <p className="text-sm text-white/80">
              {user.username}
              <span className="ml-2 rounded-full bg-white/10 px-2 py-0.5 text-xs">{user.role}</span>
            </p>
            <button
              onClick={logout}
              className="rounded-md px-3 py-1.5 text-sm font-medium text-white/90 hover:bg-white/10 hover:text-white"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-5xl p-6">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="max-w-prose text-sm text-slate-600">{panel.brief}</p>
          <p className="flex items-center gap-1.5 font-ledger text-xs text-slate-500">
            <span className="live-dot inline-block h-2 w-2 rounded-full bg-ok" />
            Live
          </p>
        </div>
        {notice ? (
          <p role="alert" className="mt-4 border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-deny">
            {notice}
          </p>
        ) : null}

        <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-5">
          {(
            [
              ['Active sites', stats.data?.sites],
              ['Live gates', stats.data?.gates],
              ['Crossings · 24h', stats.data?.crossings_24h],
              ['Pending press', stats.data?.pending_kyc],
              ['Open cases', stats.data?.open_incidents],
            ] as const
          ).map(([label, value]) => (
            <div key={label} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <p className="font-ledger text-2xl tabular-nums">{value ?? '—'}</p>
              <p className="mt-1 text-xs text-slate-500">{label}</p>
            </div>
          ))}
        </div>

        <TrendsSurge siteId={activeSiteId} canConfigure={canWrite} />

        <section className="mt-8">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-2xl font-semibold tracking-tight">Protest sites</h2>
            <input
              className="ml-auto border border-slate-300 bg-white px-3 py-1.5 text-sm"
              placeholder="Search sites…"
              value={siteSearch}
              onChange={(e) => setSiteSearch(e.target.value)}
            />
            {canWrite ? (
              <button
                onClick={() => setShowArchivedSites((v) => !v)}
                className="border border-slate-300 bg-white px-2 py-1 text-xs font-medium hover:border-slate-400"
              >
                {showArchivedSites ? 'Hide archived' : 'Show archived'}
              </button>
            ) : null}
          </div>
          {sitesQuery.isLoading ? <p className="mt-2">Loading sites…</p> : null}
          {sitesQuery.isError ? (
            <p role="alert" className="mt-2 text-deny">
              {sitesQuery.error instanceof Error && sitesQuery.error.message
                ? `Sites would not load — ${sitesQuery.error.message}`
                : 'Sites would not load. Check the API connection.'}
            </p>
          ) : null}
          {sites.length > 0 ? (
            <div className="mt-3 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
              <table className="w-full table-fixed text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-left text-xs text-slate-500">
                    <th className="w-[45%] px-4 py-2.5 font-medium">Site</th>
                    <th className="hidden w-[25%] px-4 py-2.5 font-medium sm:table-cell">Location</th>
                    <th className="hidden w-[12%] px-4 py-2.5 font-medium md:table-cell">Created</th>
                    <th className="w-[10%] px-4 py-2.5 font-medium">Status</th>
                    <th className="w-[8%] px-4 py-2.5" />
                  </tr>
                </thead>
                <tbody>
                  {sites.map((site) => (
                    <tr
                      key={site.id}
                      onClick={() => setSiteId(site.id)}
                      className={`cursor-pointer border-b border-slate-100 transition-colors last:border-0 ${
                        activeSiteId === site.id ? 'bg-blue-50' : 'hover:bg-slate-50'
                      } ${site.archived_at ? 'opacity-60' : ''}`}
                    >
                      <td className="max-w-0 px-4 py-2.5">
                        <span className="block truncate font-medium" title={site.name}>
                          {site.name}
                        </span>
                      </td>
                      <td className="hidden max-w-40 truncate px-4 py-2.5 text-slate-500 sm:table-cell">
                        {site.location || '—'}
                      </td>
                      <td className="hidden whitespace-nowrap px-4 py-2.5 font-ledger text-xs text-slate-500 md:table-cell">
                        {new Date(site.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-2.5">
                        {site.archived_at ? (
                          <span className="border border-rose-200 bg-rose-50 px-1.5 py-0.5 text-[10px] font-medium text-deny">
                            Archived
                          </span>
                        ) : (
                          <span className="border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-[10px] font-medium text-ok">
                            Active
                          </span>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-4 py-2.5 text-right">
                        {canWrite ? (
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              flipSite(site)
                            }}
                            className="border border-slate-300 bg-white px-2 py-0.5 text-[11px] font-medium hover:border-slate-400"
                          >
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
            <form onSubmit={createSite} className="mt-4 flex flex-wrap items-end gap-3">
              <label className="flex flex-col gap-1 text-sm">
                New site
                <input
                  className="border border-slate-300 bg-white px-3 py-2"
                  value={newSite.name}
                  onChange={(e) => setNewSite({ ...newSite, name: e.target.value })}
                  placeholder="e.g. Ramlila Maidan"
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                Location
                <input
                  className="border border-slate-300 bg-white px-3 py-2"
                  value={newSite.location}
                  onChange={(e) => setNewSite({ ...newSite, location: e.target.value })}
                  placeholder="City"
                />
              </label>
              <button type="submit" className="bg-signal px-4 py-2 text-sm font-medium text-white hover:bg-signal-deep">
                Add site
              </button>
            </form>
          ) : null}
        </section>

        <section className="mt-8">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-2xl font-semibold tracking-tight">Gates</h2>
            {activeSiteId !== null ? (
              <span className="text-sm text-slate-500">
                {(gatesQuery.data ?? []).length} at selected site
              </span>
            ) : null}
            <input
              className="ml-auto border border-slate-300 bg-white px-3 py-1.5 text-sm"
              placeholder="Search gates…"
              value={gateSearch}
              onChange={(e) => setGateSearch(e.target.value)}
            />
            {canWrite ? (
              <button
                onClick={() => setShowArchivedGates((v) => !v)}
                className="border border-slate-300 bg-white px-2 py-1 text-xs font-medium hover:border-slate-400"
              >
                {showArchivedGates ? 'Hide archived' : 'Show archived'}
              </button>
            ) : null}
          </div>
          {activeSiteId === null ? (
            <p className="mt-2 text-slate-500">Select a site above to see its gates.</p>
          ) : gatesQuery.isLoading ? (
            <p className="mt-2">Loading gates…</p>
          ) : gatesQuery.isError ? (
            <p className="mt-2 text-deny">Gates would not load.</p>
          ) : (gatesQuery.data ?? []).length === 0 ? (
            <p className="mt-2 text-slate-500">No gates posted at this site yet.</p>
          ) : (
            <div className="mt-3 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
              <table className="w-full table-fixed text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-left text-xs text-slate-500">
                    <th className="w-[40%] px-4 py-2.5 font-medium">Gate</th>
                    <th className="w-[15%] px-4 py-2.5 font-medium">Direction</th>
                    <th className="w-[15%] px-4 py-2.5 font-medium">Duty officer</th>
                    <th className="hidden w-[15%] px-4 py-2.5 font-medium sm:table-cell">Created</th>
                    <th className="px-4 py-2.5 font-medium">Status</th>
                    <th className="px-4 py-2.5" />
                  </tr>
                </thead>
                <tbody>
                  {(gatesQuery.data ?? []).map((gate) => (
                    <tr
                      key={gate.id}
                      onClick={() => setGateId(gate.id)}
                      className={`cursor-pointer border-b border-slate-100 transition-colors last:border-0 ${
                        gateId === gate.id ? 'bg-blue-50' : 'hover:bg-slate-50'
                      } ${gate.archived_at ? 'opacity-60' : ''}`}
                    >
                      <td className="px-4 py-2.5">
                        <span className="flex items-center gap-2 font-medium">
                          {gate.name}
                          {gateId === gate.id ? (
                            <span className="text-xs font-medium text-signal">selected</span>
                          ) : null}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-slate-500 first-letter:uppercase">{gate.direction}</td>
                      <td className="px-4 py-2.5" onClick={(e) => e.stopPropagation()}>
                        {canWrite ? (
                          <select
                            className="w-full max-w-40 border border-slate-300 bg-white px-1 py-0.5 text-xs"
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
                      <td className="px-4 py-2.5">
                        {gate.archived_at ? (
                          <span className="border border-rose-200 bg-rose-50 px-1.5 py-0.5 text-[10px] font-medium text-deny">
                            Archived
                          </span>
                        ) : (
                          <span className="border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-[10px] font-medium text-ok">
                            Active
                          </span>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-4 py-2.5 text-right">
                        {canWrite ? (
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              flipGate(gate)
                            }}
                            className="border border-slate-300 bg-white px-2 py-0.5 text-[11px] font-medium hover:border-slate-400"
                          >
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
            <form
              onSubmit={createGate}
              className="mt-4 flex flex-wrap items-end gap-3"
            >
              <label className="flex flex-col gap-1 text-sm">
                Site
                <select
                  className="border border-slate-300 bg-white px-3 py-2"
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
                  className="border border-slate-300 bg-white px-3 py-2"
                  value={newGate.name}
                  onChange={(e) => setNewGate({ ...newGate, name: e.target.value })}
                  placeholder="e.g. North A"
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                Direction
                <select
                  className="border border-slate-300 bg-white px-3 py-2"
                  value={newGate.direction}
                  onChange={(e) => setNewGate({ ...newGate, direction: e.target.value })}
                >
                  <option value="entry">Entry</option>
                  <option value="exit">Exit</option>
                  <option value="both">Both</option>
                </select>
              </label>
              <button type="submit" className="bg-signal px-4 py-2 text-sm font-medium text-white hover:bg-signal-deep">
                Post gate
              </button>
            </form>
          ) : null}
        </section>
        {(user.role === 'VerificationOfficer' || user.role === 'SuperAdmin') && <ReviewDesk />}
        {user.role === 'VerificationOfficer' && <DutyPanel />}
        {(user.role === 'GateOperator' || user.role === 'SuperAdmin' || user.role === 'SiteCommander') && (
          <Kiosk siteId={activeSiteId} gateId={gateId} />
        )}
        {(user.role === 'ForensicAnalyst' || user.role === 'SuperAdmin') && (
          <ForensicBench siteId={activeSiteId} />
        )}
        {(user.role === 'SuperAdmin' || user.role === 'SiteCommander') && (
          <AuditTrail siteId={activeSiteId} global={user.role === 'SuperAdmin'} />
        )}
        {user.role === 'SuperAdmin' && <RetentionPanel siteId={activeSiteId} />}
        {user.role === 'SuperAdmin' && <OperatorsPanel />}
        <PasswordDialog />
      </div>
    </main>
  )
}
