//! Triage verdicts submitted by agents for detection findings.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Triage verdict classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageVerdict {
    /// Confirmed malicious — escalate.
    TruePositive,
    /// Not malicious — suppress future occurrences.
    FalsePositive,
    /// Legitimate activity — no action needed.
    Benign,
    /// Insufficient information — keep active.
    NeedsInvestigation,
}

/// A verdict submitted by an agent for a detection finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    /// Unique verdict identifier.
    pub id: Uuid,
    /// The finding this verdict applies to.
    pub finding_id: Uuid,
    /// The triage classification.
    pub verdict: TriageVerdict,
    /// ID of the agent that submitted this verdict.
    pub agent_id: String,
    /// Agent's reasoning for the verdict.
    pub reasoning: String,
    /// Confidence score (0.0–1.0).
    pub confidence: f64,
    /// When this verdict was created (epoch nanos).
    pub created_at: i64,
}

impl Verdict {
    /// Create a new verdict with a fresh UUIDv7 and current timestamp.
    pub fn new(
        finding_id: Uuid,
        verdict: TriageVerdict,
        agent_id: impl Into<String>,
        reasoning: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            finding_id,
            verdict,
            agent_id: agent_id.into(),
            reasoning: reasoning.into(),
            confidence,
            created_at: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_creation() {
        let finding_id = Uuid::now_v7();
        let v = Verdict::new(
            finding_id,
            TriageVerdict::TruePositive,
            "agent-1",
            "matched known C2 pattern",
            0.95,
        );
        assert!(!v.id.is_nil());
        assert_eq!(v.finding_id, finding_id);
        assert_eq!(v.verdict, TriageVerdict::TruePositive);
        assert_eq!(v.agent_id, "agent-1");
        assert!(v.confidence > 0.9);
        assert!(v.created_at > 0);
    }

    #[test]
    fn verdict_serde_roundtrip() {
        let v = Verdict::new(
            Uuid::now_v7(),
            TriageVerdict::FalsePositive,
            "agent-2",
            "known scanner",
            0.8,
        );
        let json = serde_json::to_string(&v).unwrap();
        let deser: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.id, v.id);
        assert_eq!(deser.verdict, TriageVerdict::FalsePositive);
        assert_eq!(deser.confidence, 0.8);
    }

    #[test]
    fn triage_verdict_all_variants_serde() {
        let variants = [
            TriageVerdict::TruePositive,
            TriageVerdict::FalsePositive,
            TriageVerdict::Benign,
            TriageVerdict::NeedsInvestigation,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let deser: TriageVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(&deser, variant);
        }
    }
}
