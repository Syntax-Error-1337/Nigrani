use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Lifecycle of a press/media KYC application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KycStatus {
    Pending,
    Approved,
    Rejected,
}

impl KycStatus {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DocumentType {
    Aadhaar,
    Pan,
    #[serde(rename = "press_id")]
    PressId,
}

impl DocumentType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "aadhaar" => Some(Self::Aadhaar),
            "pan" => Some(Self::Pan),
            "press_id" => Some(Self::PressId),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aadhaar => "aadhaar",
            Self::Pan => "pan",
            Self::PressId => "press_id",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KycApplication {
    pub id: Uuid,
    pub full_name: String,
    pub organization: String,
    pub document_type: DocumentType,
    pub document_number: String,
    pub photo_url: String,
    pub status: KycStatus,
    pub submitted_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: Option<Uuid>,
    pub decision_note: String,
    /// Decided (non-pending) rows sharing this document's blind index,
    /// excluding self. Zero for first-timers; reviewers see repeat applicants.
    #[serde(default)]
    pub prior_decisions: i64,
}

/// Cryptographically signed press-card payload encoded into the QR code.
/// HMAC-SHA256 over `{application_id, full_name, organization, issued_at}`
/// with the server JWT secret; gates verify offline-free via re-check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PressCard {
    pub application_id: Uuid,
    pub full_name: String,
    pub organization: String,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}
