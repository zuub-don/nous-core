use serde::{Deserialize, Serialize};

use crate::error::{NousError, Result};

/// OCSF-aligned severity levels (0-5).
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    #[default]
    Unknown = 0,
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl Severity {
    /// Create from a numeric ID (OCSF severity_id).
    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Info),
            2 => Ok(Self::Low),
            3 => Ok(Self::Medium),
            4 => Ok(Self::High),
            5 => Ok(Self::Critical),
            other => Err(NousError::InvalidSeverity(other)),
        }
    }

    /// Numeric ID for this severity.
    pub fn id(self) -> u8 {
        self as u8
    }

    /// Short label (e.g., "CRIT", "HIGH").
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "UNKN",
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MED",
            Self::High => "HIGH",
            Self::Critical => "CRIT",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_roundtrip() {
        for id in 0..=5u8 {
            let sev = Severity::from_id(id).unwrap();
            assert_eq!(sev.id(), id);
        }
    }

    #[test]
    fn severity_invalid_id() {
        assert!(Severity::from_id(6).is_err());
        assert!(Severity::from_id(255).is_err());
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
        assert!(Severity::Info > Severity::Unknown);
    }

    #[test]
    fn severity_serde_roundtrip() {
        let sev = Severity::Critical;
        let json = serde_json::to_string(&sev).unwrap();
        let deser: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, deser);
    }
}
