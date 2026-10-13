import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './session'

export interface Site {
  id: string
  name: string
  location: string
  created_at: string
}

export interface Gate {
  id: string
  site_id: string
  name: string
  direction: 'entry' | 'exit' | 'both'
  created_at: string
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
export function useSites() {
  return useQuery({ queryKey: ['sites'], queryFn: () => getJson<Site[]>('/sites') })
}

export function useGates(siteId: string | null) {
  return useQuery({
    queryKey: ['gates', siteId],
    queryFn: () => getJson<Gate[]>(`/sites/${siteId}/gates`),
    enabled: siteId !== null,
  })
}
