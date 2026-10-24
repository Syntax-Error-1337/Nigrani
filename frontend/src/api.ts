import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './session'

export interface Site {
  id: string
  name: string
  location: string
  created_at: string
  archived_at: string | null
}

export interface Gate {
  id: string
  site_id: string
  name: string
  direction: 'entry' | 'exit' | 'both'
  created_at: string
  archived_at: string | null
  duty_officer?: string | null
  duty_username?: string | null
}

async function getJson<T>(path: string): Promise<T> {
  const res = await apiFetch(path)
  if (!res.ok) {
    const body: unknown = await res.json().catch(() => ({}))
    throw new Error(errorMessage(body, `request failed: ${res.status}`))
  }
  return res.json() as Promise<T>
}

function errorMessage(body: unknown, fallback: string): string {
  if (body !== null && typeof body === 'object' && 'error' in body) {
    const err = body.error
    if (typeof err === 'string' && err.length > 0) return err
  }
  return fallback
}

// Parallel top-level fetches (no waterfall): sites list loads alongside gates
// once a site is selected; see GatesPanel for the dependent query.
export interface Stats {
  sites: number
  gates: number
  crossings_24h: number
  pending_kyc: number
  open_incidents: number
}

export function useStats() {
  return useQuery({
    queryKey: ['stats'],
    queryFn: () => getJson<Stats>('/stats'),
    refetchInterval: 30_000,
  })
}

export function useSites(q: string, showArchived = false) {
  const params = new URLSearchParams()
  if (q) params.set('q', q)
  if (showArchived) params.set('include', 'archived')
  const query = params.size > 0 ? `?${params}` : ''
  return useQuery({ queryKey: ['sites', q, showArchived], queryFn: () => getJson<Site[]>(`/sites${query}`) })
}

export function useGates(siteId: string | null, q: string, showArchived = false) {
  const params = new URLSearchParams()
  if (q) params.set('q', q)
  if (showArchived) params.set('include', 'archived')
  const query = params.size > 0 ? `?${params}` : ''
  return useQuery({
    queryKey: ['gates', siteId, q, showArchived],
    queryFn: () => getJson<Gate[]>(`/sites/${siteId}/gates${query}`),
    enabled: siteId !== null,
  })
}

export interface KycApplication {
  id: string
  full_name: string
  organization: string
  document_type: 'aadhaar' | 'pan' | 'press_id'
  document_number: string
  photo_url: string
  status: 'pending' | 'approved' | 'rejected'
  submitted_at: string
  decided_at: string | null
  decided_by: string | null
  decision_note: string
  prior_decisions: number
  card_revoked_at: string | null
}

export interface PressCard {
  application_id: string
  full_name: string
  organization: string
  issued_at: string
  signature: string
}

export function useKycQueue(status: string, q: string) {
  const extra = q ? `&q=${encodeURIComponent(q)}` : ''
  return useQuery({
    queryKey: ['kyc', status, q],
    queryFn: () => getJson<KycApplication[]>(`/kyc/applications?status=${status}${extra}`),
  })
}

export interface EntryLog {
  id: string
  gate_id: string
  application_id: string | null
  holder_name: string | null
  holder_org: string | null
  direction: 'entry' | 'exit' | 'both'
  method: 'press_card' | 'manual'
  snapshot_key: string
  recorded_by: string
  recorded_at: string
}

export function useGateLog(siteId: string | null, gateId: string | null) {
  return useQuery({
    queryKey: ['gate-log', siteId, gateId],
    queryFn: async (): Promise<EntryLog[]> => {
      const res = await apiFetch(`/sites/${siteId}/gates/${gateId}/log?limit=20`)
      if (!res.ok) throw new Error(`log failed: ${res.status}`)
      return res.json() as Promise<EntryLog[]>
    },
    enabled: siteId !== null && gateId !== null,
  })
}
