import { useQuery } from '@tanstack/react-query'
import { getJson } from '@/shared/api'

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
  card_serial: string | null
  card_expires_at: string | null
  card_print_count: number
}

export type { PressCard } from '@/shared/lib/press-card'

export function useKycQueue(status: string, q: string) {
  const extra = q ? `&q=${encodeURIComponent(q)}` : ''
  return useQuery({
    queryKey: ['kyc', status, q],
    queryFn: () => getJson<KycApplication[]>(`/kyc/applications?status=${status}${extra}`),
  })
}
