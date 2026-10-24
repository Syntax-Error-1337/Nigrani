import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { BadgeCheck, Inbox } from 'lucide-react'
import Kiosk from '@/widgets/kiosk'
import { apiFetch } from '@/shared/api'

interface DutyGate {
  gate_id: string
  gate_name: string
  direction: string
  site_id: string
  site_name: string
  archived_at: string | null
}

/// The duty console: gates the signed-in verifier is assigned to staff.
/// Pick a gate, then verify and log crossings right there.
export default function DutyPanel() {
  const [gateId, setGateId] = useState<string | null>(null)
  const roster = useQuery({
    queryKey: ['my-duty'],
    queryFn: async (): Promise<DutyGate[]> => {
      const res = await apiFetch('/my/duty')
      if (!res.ok) throw new Error(`duty failed: ${res.status}`)
      return res.json() as Promise<DutyGate[]>
    },
  })
  const gates = roster.data ?? []
  const selected = gates.find((g) => g.gate_id === gateId) ?? null
  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-1.5 text-lg font-semibold tracking-tight">
        <BadgeCheck className="h-4 w-4 text-slate-400" /> Gate duty
      </h2>
      <p className="mt-1 text-sm text-slate-500">
        Gates you are assigned to staff. Pick one to verify entrants at that post.
      </p>
      {roster.isLoading ? <p className="mt-2">Loading duty roster…</p> : null}
      {roster.isError ? (
        <p className="mt-2 text-deny">Duty roster would not load.</p>
      ) : null}
      {gates.length === 0 && !roster.isLoading && !roster.isError ? (
        <p className="mt-8 text-center text-sm text-slate-400">
          <Inbox className="mx-auto h-5 w-5" />
          <span className="mt-1 block">No duty assigned yet — a commander assigns you to a gate.</span>
        </p>
      ) : null}
      {gates.length > 0 ? (
        <div className="mt-3 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
          <ul className="divide-y divide-slate-100">
            {gates.map((g) => (
              <li key={g.gate_id}>
                <button
                  onClick={() => setGateId(g.gate_id)}
                  className={`flex w-full items-center gap-3 px-4 py-2.5 text-left text-sm transition-colors ${
                    gateId === g.gate_id ? 'bg-blue-50 font-medium' : 'hover:bg-slate-50'
                  } ${g.archived_at ? 'opacity-60' : ''}`}
                >
                  <span className="font-medium">{g.gate_name}</span>
                  <span className="text-slate-500">
                    {g.site_name} · {g.direction}
                  </span>
                  {g.archived_at ? (
                    <span className="border border-rose-200 bg-rose-50 px-1.5 py-0.5 text-[10px] font-medium text-deny">
                      Archived
                    </span>
                  ) : null}
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {selected ? <Kiosk siteId={selected.site_id} gateId={selected.gate_id} /> : null}
    </section>
  )
}
