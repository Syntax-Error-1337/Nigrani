import { useEffect, useRef, useState } from 'react'
import {
  Activity, BadgeCheck, ClipboardList, Gauge, KeyRound, LayoutDashboard, Moon, Sun,
  LogOut, Radar, Recycle, ScanLine, ShieldCheck, Network, Users,
} from 'lucide-react'
import AuditTrail from '@/widgets/audit-trail'
import DutyPanel from '@/widgets/duty-panel'
import ForensicBench from '@/widgets/forensic-bench'
import Kiosk from '@/widgets/kiosk'
import OperatorsPanel, { PasswordDialog } from '@/widgets/operators-panel'
import RetentionPanel from '@/widgets/retention-panel'
import SecurityPanel from '@/widgets/security-panel'
import ReviewDesk from '@/widgets/review-desk'
import SitesPanel from '@/widgets/sites-panel'
import TrendsSurge from '@/widgets/trends-surge'
import { useSites, useStats } from '@/entities/site'
import { useSession, type Role } from '@/shared/session'

/// Sidebar navigation sections (s-S1). `roles` gates visibility; the
/// section content reuses the role rules the panels already enforce.
const NAV: { key: string; label: string; icon: typeof Gauge; roles: Role[]; brief: string }[] = [
  { key: 'overview', label: 'Overview', icon: LayoutDashboard, roles: ['SuperAdmin', 'SiteCommander', 'VerificationOfficer', 'GateOperator', 'ForensicAnalyst'], brief: 'Live status — sites, gates, crossings, and open cases.' },
  { key: 'sites', label: 'Sites & gates', icon: Network, roles: ['SuperAdmin', 'SiteCommander', 'VerificationOfficer', 'GateOperator', 'ForensicAnalyst'], brief: 'Sites, gates, and duty rosters. Create protest sites and their entry posts here.' },
  { key: 'kiosk', label: 'Gate kiosk', icon: ScanLine, roles: ['SuperAdmin', 'SiteCommander', 'GateOperator'], brief: 'Verify arrivals against the gate roster. Select your post to begin screening.' },
  { key: 'review', label: 'Press review desk', icon: ClipboardList, roles: ['SuperAdmin', 'VerificationOfficer'], brief: 'Media access requests land here for inspection and approval.' },
  { key: 'duty', label: 'Duty roster', icon: BadgeCheck, roles: ['VerificationOfficer'], brief: 'Gates you are assigned to staff — verify entrants at your post.' },
  { key: 'bench', label: 'Forensic bench', icon: Radar, roles: ['SuperAdmin', 'ForensicAnalyst'], brief: 'Similarity search over gate captures, incident log, and gate heatmap.' },
  { key: 'audit', label: 'Audit trail', icon: ShieldCheck, roles: ['SuperAdmin', 'SiteCommander'], brief: 'Append-only action ledger — verify the hash chain or anchor the head.' },
  { key: 'retention', label: 'Retention', icon: Recycle, roles: ['SuperAdmin'], brief: 'Purge schedules per entity, snapshot orphans, and site export packs.' },
  { key: 'operators', label: 'Operators', icon: Users, roles: ['SuperAdmin'], brief: 'Provision accounts, activate/deactivate, unlock, and sign out sessions.' },
  { key: 'security', label: 'Security', icon: KeyRound, roles: ['SuperAdmin', 'SiteCommander', 'VerificationOfficer', 'GateOperator', 'ForensicAnalyst'], brief: 'Your sessions and two-factor setup.' },
]

export default function Dashboard() {
  const user = useSession((s) => s.user)
  const logout = useSession((s) => s.logout)
  const [section, setSection] = useState('overview')
  const [siteId, setSiteId] = useState<string | null>(null)
  const [gateId, setGateId] = useState<string | null>(null)

  function setTextSize(size: 'sm' | 'md' | 'lg') {
    // GIGW pattern: user-controlled text scale on the root element, persisted.
    const scale = size === 'sm' ? '87.5%' : size === 'lg' ? '112.5%' : '100%'
    document.documentElement.style.fontSize = scale
    localStorage.setItem('sg-textsize', size)
  }
  // Restore the persisted scale before first paint of the console.
  useEffect(() => {
    const saved = localStorage.getItem('sg-textsize') as 'sm' | 'md' | 'lg' | null
    if (saved) setTextSize(saved)
  }, [])

  const [dark, setDark] = useState(() =>
    localStorage.getItem('sg-theme')
      ? localStorage.getItem('sg-theme') === 'dark'
      : window.matchMedia('(prefers-color-scheme: dark)').matches,
  )
  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
    localStorage.setItem('sg-theme', dark ? 'dark' : 'light')
  }, [dark])

  // Full topology (unfiltered): fallback selection + the topbar site picker.
  const sitesQuery = useSites('', false)
  const stats = useStats()

  // The gates table (and everything scoped to it) follows the EFFECTIVE
  // site — explicit selection, else the first site. Hook must stay above
  // the `if (!user)` return.
  const sites = sitesQuery.data ?? []
  const activeSiteId = siteId ?? sites[0]?.id ?? null

  // A selected gate belongs to exactly one site; switching sites would leave
  // a mismatched (site, gate) pair posting crossings to the wrong post.
  const prevSiteRef = useRef<string | null>(null)
  useEffect(() => {
    if (prevSiteRef.current !== null && prevSiteRef.current !== activeSiteId) {
      setGateId(null)
    }
    prevSiteRef.current = activeSiteId
  }, [activeSiteId])

  if (!user) return null
  const canWrite = user.role === 'SuperAdmin' || user.role === 'SiteCommander'
  const nav = NAV.filter((n) => n.roles.includes(user.role))
  const current = nav.find((n) => n.key === section) ?? nav[0]
  const activeSite = sites.find((s) => s.id === activeSiteId)

  const SitePicker = (
    <label className="flex items-center gap-2 text-sm">
      <span className="hidden text-xs text-white/60 sm:block">Site</span>
      <select
        value={activeSiteId ?? ''}
        onChange={(e) => setSiteId(e.target.value || null)}
        className="rounded-lg border border-white/15 bg-white/10 px-2 py-1 text-xs text-white"
        aria-label="Active site"
      >
        {sites.map((s) => (
          <option key={s.id} value={s.id} className="text-ink">
            {s.name}
          </option>
        ))}
      </select>
    </label>
  )

  const kpis = (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-5">
      {(
        [
          ['Active sites', stats.data?.sites],
          ['Live gates', stats.data?.gates],
          ['Crossings · 24h', stats.data?.crossings_24h],
          ['Pending press', stats.data?.pending_kyc],
          ['Open cases', stats.data?.open_incidents],
        ] as const
      ).map(([label, value]) => (
        <div
          key={label}
          className="group rounded-xl border border-slate-200 bg-white p-4 shadow-sm transition-shadow hover:shadow-md"
        >
          <p className="font-ledger text-3xl tabular-nums leading-none">
            {value === undefined
              ? <span className="skeleton h-8 w-14" aria-label="loading" />
              : value}
          </p>
          <p className="mt-2 flex items-center gap-1.5 text-xs text-slate-500">
            <Activity className="h-3 w-3 text-saffron opacity-0 transition-opacity group-hover:opacity-100" />
            {label}
          </p>
        </div>
      ))}
    </div>
  )

  return (
    <div className="min-h-screen bg-paper" id="main-content">
      {/* --- Sidebar (s-S1): fixed navy rail, role-scoped nav --- */}
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-60 flex-col border-r border-white/5 bg-navy text-white md:flex">
        <div className="tricolor-strip h-1 w-full" />
        <div className="flex items-center gap-2 px-5 py-4">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-saffron/90 font-semibold text-navy">नि</span>
          <div>
            <p className="text-sm font-semibold tracking-tight">Nigrani</p>
            <p className="text-[10px] text-white/70">निगरानी · operations console</p>
          </div>
        </div>
        <nav aria-label="Console sections" className="flex-1 space-y-0.5 overflow-y-auto px-3 py-2">
          {nav.map((n) => (
            <button
              key={n.key}
              onClick={() => setSection(n.key)}
              aria-current={current.key === n.key ? 'page' : undefined}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors ${
                current.key === n.key
                  ? 'bg-white/15 font-medium text-white'
                  : 'text-white/70 hover:bg-white/5 hover:text-white'
              }`}
            >
              <n.icon className={`h-4 w-4 ${current.key === n.key ? 'text-saffron' : 'text-white/50'}`} />
              {n.label}
            </button>
          ))}
        </nav>
        <div className="border-t border-white/10 px-5 py-3 text-xs text-white/70">
          <p className="font-medium text-white">{user.username}</p>
          <p className="mt-0.5">{user.role}</p>
        </div>
      </aside>

      {/* --- Mobile nav: horizontal chips under the topbar --- */}
      <div className="md:pl-60">
        <header className="sticky top-0 z-10 bg-navy text-white shadow-sm">
          <div className="tricolor-strip h-1 w-full" />
          <div className="flex items-center justify-between px-6 py-2.5">
            <div className="flex items-baseline gap-2 text-sm font-semibold tracking-tight md:hidden">
              <span className="inline-block h-2.5 w-2.5 rounded-full bg-saffron" />
              Nigrani
            </div>
            <div className="hidden items-center gap-3 md:flex">
              <h1 className="text-sm font-medium text-white/90">{current.label}</h1>
              <div className="h-4 w-px bg-white/10" />
              <p className="max-w-md truncate text-xs text-white/60">{current.brief}</p>
            </div>
            <div className="flex items-center gap-3">
              {sites.length > 0 ? SitePicker : null}
              <button
                onClick={() => setDark((v) => !v)}
                aria-label={dark ? 'Switch to light theme' : 'Switch to dark theme'}
                className="rounded-lg p-1.5 text-white/80 transition-colors hover:bg-white/10 hover:text-white"
              >
                {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
              </button>
              <div className="flex items-center gap-1 font-ledger text-xs" role="group" aria-label="Text size">
                {/* Visible text leads the accessible name (axe: label-content-name-mismatch). */}
                <button onClick={() => setTextSize('sm')} className="rounded px-1.5 py-0.5 hover:bg-white/10">A−<span className="sr-only"> smaller text</span></button>
                <button onClick={() => setTextSize('md')} className="rounded px-1.5 py-0.5 hover:bg-white/10">A<span className="sr-only"> normal text</span></button>
                <button onClick={() => setTextSize('lg')} className="rounded px-1.5 py-0.5 hover:bg-white/10">A+<span className="sr-only"> larger text</span></button>
              </div>
              <button
                onClick={logout}
                className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium text-white/90 hover:bg-white/10 hover:text-white"
              >
                <LogOut className="h-3.5 w-3.5" />
                <span className="hidden sm:block">Sign out</span>
              </button>
            </div>
          </div>
          {/* Mobile chips mirror the sidebar */}
          <nav aria-label="Console sections" className="flex gap-1.5 overflow-x-auto px-4 pb-2 md:hidden">
            {nav.map((n) => (
              <button
                key={n.key}
                onClick={() => setSection(n.key)}
                aria-current={current.key === n.key ? 'page' : undefined}
                className={`whitespace-nowrap rounded-full px-3 py-1 text-xs transition-colors ${
                  current.key === n.key ? 'bg-white/15 font-medium text-white' : 'text-white/60 hover:bg-white/5'
                }`}
              >
                {n.label}
              </button>
            ))}
          </nav>
        </header>

        <main className="mx-auto max-w-6xl p-6">
          {/* Section heading on mobile (topbar hides it there) */}
          <div className="mb-4 flex flex-wrap items-center justify-between gap-2 md:hidden">
            <p className="text-lg font-semibold tracking-tight">{current.label}</p>
          </div>
          <div className="mb-4 hidden items-center gap-2 text-xs text-slate-500 md:flex">
            <span className="live-dot inline-block h-2 w-2 rounded-full bg-ok" />
            Live
            {activeSite ? (
              <>
                <span>·</span>
                <span>
                  Active site: <span className="font-medium text-slate-700">{activeSite.name}</span>
                  {activeSite.location ? ` — ${activeSite.location}` : ''}
                </span>
              </>
            ) : null}
          </div>

          {current.key === 'overview' ? (
            <>
              {kpis}
              <TrendsSurge siteId={activeSiteId} canConfigure={canWrite} />
            </>
          ) : null}
          {current.key === 'sites' ? (
            <SitesPanel
              sites={sites}
              sitesLoading={sitesQuery.isLoading}
              sitesError={sitesQuery.isError}
              refetchSites={() => void sitesQuery.refetch()}
              siteId={siteId}
              gateId={gateId}
              onSelectSite={setSiteId}
              onSelectGate={setGateId}
              canWrite={canWrite}
            />
          ) : null}
          {current.key === 'kiosk' ? <Kiosk siteId={activeSiteId} gateId={gateId} onPickGate={setGateId} /> : null}
          {current.key === 'review' ? <ReviewDesk /> : null}
          {current.key === 'duty' ? <DutyPanel /> : null}
          {current.key === 'bench' ? <ForensicBench siteId={activeSiteId} /> : null}
          {current.key === 'audit' ? (
            <AuditTrail siteId={activeSiteId} global={user.role === 'SuperAdmin'} />
          ) : null}
          {current.key === 'retention' ? <RetentionPanel siteId={activeSiteId} /> : null}
          {current.key === 'operators' ? <OperatorsPanel /> : null}
          {current.key === 'security' ? (
            <>
              <SecurityPanel />
              <PasswordDialog />
            </>
          ) : null}
        </main>
      </div>
    </div>
  )
}
