// Wire type shared with the kiosk outbox — lives here (shared/lib) so that
// shared code can reference it; entities/kyc re-exports it as the public API.
export interface PressCard {
  application_id: string
  full_name: string
  organization: string
  issued_at: string
  signature: string
}
