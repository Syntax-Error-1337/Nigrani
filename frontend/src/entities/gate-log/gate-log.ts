import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/shared/api'

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
