import { useState } from 'react'
import { RefreshCcw, TriangleAlert, XCircle } from 'lucide-react'
import { apiFetch } from '@/shared/api'
import { useSurge, useTrends } from '@/entities/site'

const WINDOWS = [24, 72, 168] as const

function fmtHour(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric' })
}

/// Occupancy trends (hourly entry/exit bars over a selectable window) and
/// per-site surge alerting: threshold configuration, recent alerts, live
/// banner. REST is the source of truth; the stream only invalidates.
export default function TrendsSurge({
  siteId,
  canConfigure,
}: {
  siteId: string | null
  canConfigure: boolean
}) {
  const [hours, setHours] = useState<(typeof WINDOWS)[number]>(24)
  const trends = useTrends(siteId, hours)
  const surge = useSurge(siteId)
  const [thresholdInput, setThresholdInput] = useState('')
  const [notice, setNotice] = useState<string | null>(null)

  async function saveThreshold(value: number | null) {
    setNotice(null)
    const res = await apiFetch(`/sites/${siteId}/surge`, {
      method: 'POST',
      body: JSON.stringify({ threshold: value }),
    })
    if (!res.ok) {
      const body: unknown = await res.json().catch(() => ({}))
      const err = body !== null && typeof body === 'object' && 'error' in body ? body.error : null
      setNotice(typeof err === 'string' && err.length > 0 ? err : 'Could not set surge threshold')
      return
    }
    surge.refetch()
  }

  const buckets = trends.data ?? []
  const peak = Math.max(1, ...buckets.map((b) => b.entries + b.exits))
  const alerts = surge.data?.alerts ?? []
  const threshold = surge.data?.threshold ?? null

  return (
    <section className="mt-8">
      <div className="flex flex-wrap items-center gap-3">
        
        <span className="text-sm text-slate-500">hourly crossings · {siteId === null ? 'no site selected' : `${hours}h window`}</span>
        <div className="ml-auto flex gap-1" role="group" aria-label="Trend window">
          {WINDOWS.map((h) => (
            <button
              key={h}
              onClick={() => setHours(h)}
              className={
                'rounded-full border px-2.5 py-1 text-xs font-medium transition-colors ' +
                (hours === h ? 'border-signal bg-signal text-white' : 'border-slate-300 bg-white text-slate-600 hover:border-slate-400 hover:bg-slate-50')
              }
            >
              {h}h
            </button>
          ))}
        </div>
      </div>

      {siteId !== null && surge.data?.alerts.length ? (
        <div role="alert" className="mt-3 rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm">
          <p className="flex items-center gap-1.5 font-semibold text-saffron-ink">
            <TriangleAlert className="h-3.5 w-3.5" /> Surge alerts · last 24h
          </p>
          <ul className="mt-1 list-inside list-disc">
            {alerts.map((a) => (
              <li key={a.id}>
                {a.gate_name}: {a.count} entries by {fmtHour(a.window_start)} (threshold {a.threshold}/hour)
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {siteId !== null ? (
        <>
          {trends.isLoading ? (
            <p className="mt-2 flex items-center gap-2 text-sm text-slate-500">
              <RefreshCcw className="h-3.5 w-3.5 animate-spin" /> Loading trend…
            </p>
          ) : null}
          {trends.isError ? <p role="alert" className="mt-2 text-deny">Trend would not load.</p> : null}
          {buckets.length > 0 ? (
            <div className="mt-4 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="flex items-center justify-between text-xs text-slate-500">
                <span className="flex items-center gap-3">
                  <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-signal-deep" /> in+out per hour</span>
                  <span className="font-ledger">peak {peak}/h</span>
                </span>
                <span>{buckets.length} hourly {buckets.length === 1 ? 'bucket' : 'buckets'}</span>
              </div>
              <div className="mt-3 flex h-40 items-end gap-[3px] border-b border-slate-200 pb-px" aria-label="Hourly crossings chart" role="img">
                {buckets.map((b) => {
                  const total = b.entries + b.exits
                  const pct = Math.max(total === 0 ? 0 : 3, Math.round((total / peak) * 100))
                  return (
                    <div
                      key={b.hour}
                      className="group/bar relative max-w-7 flex-1 rounded-t-sm bg-gradient-to-t from-signal-deep/85 to-signal transition-[filter] hover:brightness-125"
                      style={{ height: `${pct}%`, minWidth: 3 }}
                      title={`${fmtHour(b.hour)} — ${b.entries} in / ${b.exits} out`}
                    />
                  )
                })}
              </div>
              <div className="mt-1 flex justify-between font-ledger text-[10px] text-slate-400">
                <span>{fmtHour(buckets[0].hour)}</span>
                <span>{fmtHour(buckets[buckets.length - 1].hour)}</span>
              </div>
            </div>
          ) : null}
          {buckets.length === 0 && !trends.isLoading && !trends.isError ? (
            <p className="mt-2 text-sm text-slate-500">No crossings in this window.</p>
          ) : null}

          {canConfigure ? (
            <form
              className="mt-3 flex flex-wrap items-center gap-2"
              onSubmit={(e) => {
                e.preventDefault()
                const n = Number(thresholdInput)
                if (thresholdInput === '') return
                if (!Number.isInteger(n) || n < 1 || n > 10_000) {
                  setNotice('Threshold must be 1..=10000 entries/hour')
                  return
                }
                void saveThreshold(n)
              }}
            >
              <label className="text-sm text-slate-600" htmlFor="surge-threshold">
                Surge threshold (entries/hour/gate)
              </label>
              <input
                id="surge-threshold"
                className="input w-24"
                placeholder={threshold === null ? 'off' : String(threshold)}
                value={thresholdInput}
                onChange={(e) => setThresholdInput(e.target.value)}
                inputMode="numeric"
              />
              <button type="submit" className="btn btn-primary">
                Set
              </button>
              {threshold !== null ? (
                <button
                  type="button"
                  onClick={() => {
                    setThresholdInput('')
                    void saveThreshold(null)
                  }}
                  className="btn btn-secondary"
                >
                  Clear
                </button>
              ) : null}
              <span className="text-sm text-slate-500">
                {threshold === null ? 'Alerting off' : `Alerting over ${threshold}/hour/gate`}
              </span>
            </form>
          ) : null}
          {notice ? (
            <p role="alert" className="mt-2 flex items-center gap-2 rounded-xl border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-deny">
              <XCircle className="h-4 w-4 shrink-0" />
              {notice}
            </p>
          ) : null}
        </>
      ) : null}
    </section>
  )
}
