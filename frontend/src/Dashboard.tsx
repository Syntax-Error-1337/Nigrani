import { useState } from 'react'
import AuditTrail from './AuditTrail'
import RetentionPanel from './RetentionPanel'
import ForensicBench from './ForensicBench'
import Kiosk from './Kiosk'
import ReviewDesk from './ReviewDesk'
import { useGates, useSites } from './api'
import { apiFetch, useSession, type Role } from './session'

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
  const sitesQuery = useSites()
  const [siteId, setSiteId] = useState<string | null>(null)
  const gatesQuery = useGates(siteId)
  const [gateId, setGateId] = useState<string | null>(null)
  const [newSite, setNewSite] = useState({ name: '', location: '' })
  const [newGate, setNewGate] = useState({ name: '', direction: 'entry' })
  const [notice, setNotice] = useState<string | null>(null)

  if (!user) return null
  const panel = ROLE_PANELS[user.role]
  const canWrite = user.role === 'SuperAdmin' || user.role === 'SiteCommander'
  const sites = sitesQuery.data ?? []
  const activeSiteId = siteId ?? sites[0]?.id ?? null

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
    if (!activeSiteId) return
    setNotice(null)
    const res = await apiFetch(`/sites/${activeSiteId}/gates`, {
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
    gatesQuery.refetch()
  }

  return (
    <main className="min-h-screen bg-paper">
      <header className="flex items-center justify-between border-b-2 border-ink bg-ink px-6 py-4 text-paper">
        <div>
          <p className="font-ledger text-xs tracking-widest text-signal">NIGRANI</p>
          <h1 className="font-display text-3xl uppercase">{panel.heading}</h1>
        </div>
        <div className="flex items-center gap-4">
          <p className="font-ledger text-sm">
            {user.username} · {user.role}
          </p>
          <button onClick={logout} className="border border-paper px-3 py-1 text-sm">
            Sign out
          </button>
        </div>
      </header>

      <div className="mx-auto max-w-5xl p-6">
        <p className="max-w-prose">{panel.brief}</p>
        {notice ? (
          <p role="alert" className="mt-4 border border-deny bg-red-50 px-3 py-2 text-sm text-deny">
            {notice}
          </p>
        ) : null}

        <section className="mt-6">
          <h2 className="font-display text-2xl uppercase">Protest sites</h2>
          {sitesQuery.isLoading ? <p className="mt-2">Loading sites…</p> : null}
          {sitesQuery.isError ? (
            <p className="mt-2 text-deny">Sites would not load. Check the API connection.</p>
          ) : null}
          <ul className="mt-3 grid gap-3 md:grid-cols-2">
            {sites.map((site) => (
              <li key={site.id}>
                <button
                  onClick={() => setSiteId(site.id)}
                  className={`w-full border-2 px-4 py-3 text-left ${
                    activeSiteId === site.id ? 'border-signal bg-white' : 'border-ink bg-white'
                  }`}
                >
                  <span className="font-display text-xl uppercase">{site.name}</span>
                  <span className="block font-ledger text-xs text-neutral-500">
                    {site.location || '—'}
                  </span>
                </button>
              </li>
            ))}
          </ul>
          {canWrite ? (
            <form onSubmit={createSite} className="mt-4 flex flex-wrap items-end gap-3">
              <label className="flex flex-col gap-1 text-sm">
                New site
                <input
                  className="border border-ink px-3 py-2"
                  value={newSite.name}
                  onChange={(e) => setNewSite({ ...newSite, name: e.target.value })}
                  placeholder="e.g. Ramlila Maidan"
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                Location
                <input
                  className="border border-ink px-3 py-2"
                  value={newSite.location}
                  onChange={(e) => setNewSite({ ...newSite, location: e.target.value })}
                  placeholder="City"
                />
              </label>
              <button type="submit" className="bg-ink px-4 py-2 text-sm uppercase text-paper">
                Add site
              </button>
            </form>
          ) : null}
        </section>

        <section className="mt-8">
          <h2 className="font-display text-2xl uppercase">Gates</h2>
          {activeSiteId === null ? (
            <p className="mt-2">No site selected.</p>
          ) : gatesQuery.isLoading ? (
            <p className="mt-2">Loading gates…</p>
          ) : gatesQuery.isError ? (
            <p className="mt-2 text-deny">Gates would not load.</p>
          ) : (gatesQuery.data ?? []).length === 0 ? (
            <p className="mt-2">No gates posted at this site yet.</p>
          ) : (
            <ol className="mt-3 divide-y-2 divide-ink border-y-2 border-ink bg-white">
              {(gatesQuery.data ?? []).map((gate, i) => (
                <li key={gate.id}>
                  <button
                    onClick={() => setGateId(gate.id)}
                    className={`flex w-full items-baseline gap-4 px-4 py-3 text-left ${
                      gateId === gate.id ? 'bg-amber-50' : ''
                    }`}
                  >
                  <span className="font-display text-4xl text-signal">
                    {String(i + 1).padStart(2, '0')}
                  </span>
                  <span className="font-display text-xl uppercase">{gate.name}</span>
                    <span className="ml-auto font-ledger text-xs uppercase">{gate.direction}</span>
                  </button>
                </li>
              ))}
            </ol>
          )}
        {(user.role === 'VerificationOfficer' || user.role === 'SuperAdmin') && <ReviewDesk />}
        {(user.role === 'GateOperator' || user.role === 'SuperAdmin' || user.role === 'SiteCommander') && (
          <Kiosk siteId={activeSiteId} gateId={gateId} />
        )}
        {(user.role === 'ForensicAnalyst' || user.role === 'SuperAdmin') && (
          <ForensicBench siteId={activeSiteId} />
        )}
        {(user.role === 'SuperAdmin' || user.role === 'SiteCommander') && (
          <AuditTrail siteId={activeSiteId} global={user.role === 'SuperAdmin'} />
        )}
        {user.role === 'SuperAdmin' && <RetentionPanel />}

        {canWrite && activeSiteId ? (
            <form onSubmit={createGate} className="mt-4 flex flex-wrap items-end gap-3">
              <label className="flex flex-col gap-1 text-sm">
                New gate
                <input
                  className="border border-ink px-3 py-2"
                  value={newGate.name}
                  onChange={(e) => setNewGate({ ...newGate, name: e.target.value })}
                  placeholder="e.g. Gate 1"
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                Direction
                <select
                  className="border border-ink px-3 py-2"
                  value={newGate.direction}
                  onChange={(e) => setNewGate({ ...newGate, direction: e.target.value })}
                >
                  <option value="entry">Entry</option>
                  <option value="exit">Exit</option>
                  <option value="both">Both</option>
                </select>
              </label>
              <button type="submit" className="bg-ink px-4 py-2 text-sm uppercase text-paper">
                Post gate
              </button>
            </form>
          ) : null}
        </section>
      </div>
    </main>
  )
}
