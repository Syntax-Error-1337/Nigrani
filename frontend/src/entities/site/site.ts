import { useQuery } from '@tanstack/react-query'
import { getJson } from '@/shared/api'

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

export interface TrendBucket {
  hour: string
  entries: number
  exits: number
}

export function useTrends(siteId: string | null, hours: number) {
  return useQuery({
    queryKey: ['trends', siteId, hours],
    queryFn: () => getJson<TrendBucket[]>(`/sites/${siteId}/trends?hours=${hours}`),
    enabled: siteId !== null,
  })
}

export interface SurgeAlert {
  id: string
  gate_id: string
  gate_name: string
  window_start: string
  count: number
  threshold: number
  created_at: string
}

export interface SurgeStatus {
  threshold: number | null
  alerts: SurgeAlert[]
}

export function useSurge(siteId: string | null) {
  return useQuery({
    queryKey: ['surge', siteId],
    queryFn: () => getJson<SurgeStatus>(`/sites/${siteId}/surge`),
    enabled: siteId !== null,
  })
}
