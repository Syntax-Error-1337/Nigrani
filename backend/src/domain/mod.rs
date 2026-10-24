use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
pub mod kyc;

pub use kyc::{DocumentType, KycApplication, KycStatus, PressCard};

/// Canonical roles from the system design (stored as TEXT in `roles.name`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    SuperAdmin,
    SiteCommander,
    GateOperator,
    VerificationOfficer,
    ForensicAnalyst,
}

impl Role {
    /// Parse from the role name stored in the `roles` table.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "SuperAdmin" => Some(Self::SuperAdmin),
            "SiteCommander" => Some(Self::SiteCommander),
            "GateOperator" => Some(Self::GateOperator),
            "VerificationOfficer" => Some(Self::VerificationOfficer),
            "ForensicAnalyst" => Some(Self::ForensicAnalyst),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SuperAdmin => "SuperAdmin",
            Self::SiteCommander => "SiteCommander",
            Self::GateOperator => "GateOperator",
            Self::VerificationOfficer => "VerificationOfficer",
            Self::ForensicAnalyst => "ForensicAnalyst",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub role: Role,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub id: Uuid,
    pub name: String,
    pub location: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub archived_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gate {
    pub id: Uuid,
    pub site_id: Uuid,
    pub name: String,
    pub direction: GateDirection,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub archived_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duty_officer: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duty_username: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GateDirection {
    Entry,
    Exit,
    Both,
}

impl GateDirection {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "entry" => Some(Self::Entry),
            "exit" => Some(Self::Exit),
            "both" => Some(Self::Both),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::Exit => "exit",
            Self::Both => "both",
        }
    }
}
