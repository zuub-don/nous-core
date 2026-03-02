//! Feedback loop: applies verdicts to adjust entity risk scores and finding state.

use nous_core::entity::EntityType;
use nous_core::state::SemanticState;
use nous_core::verdict::{TriageVerdict, Verdict};

/// Apply a verdict to the semantic state, adjusting risk scores and finding status.
///
/// - TruePositive: +15 risk to associated entities, resolve finding
/// - FalsePositive: -20 risk, add suppression rule (1 hour), resolve finding
/// - Benign: -10 risk, resolve finding
/// - NeedsInvestigation: no risk change, keep active
pub fn apply_verdict(
    state: &mut SemanticState,
    verdict: &Verdict,
    finding_entities: &[(EntityType, String)],
) {
    match verdict.verdict {
        TriageVerdict::TruePositive => {
            for (et, val) in finding_entities {
                state.adjust_entity_risk(*et, val, 15);
            }
            state.resolve_finding_id(&verdict.finding_id);
        }
        TriageVerdict::FalsePositive => {
            for (et, val) in finding_entities {
                state.adjust_entity_risk(*et, val, -20);
            }
            // Suppress for 1 hour (nanos)
            let suppress_until =
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) + 3_600_000_000_000;
            state.add_suppression(verdict.finding_id.to_string(), suppress_until);
            state.resolve_finding_id(&verdict.finding_id);
        }
        TriageVerdict::Benign => {
            for (et, val) in finding_entities {
                state.adjust_entity_risk(*et, val, -10);
            }
            state.resolve_finding_id(&verdict.finding_id);
        }
        TriageVerdict::NeedsInvestigation => {
            // No risk change, keep finding active
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nous_core::entity::EntityType;
    use nous_core::verdict::Verdict;
    use uuid::Uuid;

    #[test]
    fn true_positive_increases_risk() {
        let mut state = SemanticState::new();
        let finding_id = Uuid::now_v7();
        state.add_finding_id(finding_id);
        state.update_entity_risk(EntityType::IpAddress, "10.0.0.1", 50);

        let verdict = Verdict::new(
            finding_id,
            TriageVerdict::TruePositive,
            "agent-1",
            "confirmed",
            0.9,
        );
        apply_verdict(
            &mut state,
            &verdict,
            &[(EntityType::IpAddress, "10.0.0.1".into())],
        );

        assert_eq!(
            state.entity_risk(EntityType::IpAddress, "10.0.0.1"),
            Some(65)
        );
        assert_eq!(state.active_findings(), 0);
    }

    #[test]
    fn false_positive_decreases_risk_and_suppresses() {
        let mut state = SemanticState::new();
        let finding_id = Uuid::now_v7();
        state.add_finding_id(finding_id);
        state.update_entity_risk(EntityType::IpAddress, "10.0.0.1", 50);

        let verdict = Verdict::new(
            finding_id,
            TriageVerdict::FalsePositive,
            "agent-1",
            "scanner",
            0.8,
        );
        apply_verdict(
            &mut state,
            &verdict,
            &[(EntityType::IpAddress, "10.0.0.1".into())],
        );

        assert_eq!(
            state.entity_risk(EntityType::IpAddress, "10.0.0.1"),
            Some(30)
        );
        assert_eq!(state.active_findings(), 0);
        // Should be suppressed now
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        assert!(state.is_suppressed(&finding_id.to_string(), now));
    }

    #[test]
    fn benign_decreases_risk() {
        let mut state = SemanticState::new();
        let finding_id = Uuid::now_v7();
        state.add_finding_id(finding_id);
        state.update_entity_risk(EntityType::Domain, "example.com", 40);

        let verdict = Verdict::new(finding_id, TriageVerdict::Benign, "agent-1", "ok", 0.7);
        apply_verdict(
            &mut state,
            &verdict,
            &[(EntityType::Domain, "example.com".into())],
        );

        assert_eq!(
            state.entity_risk(EntityType::Domain, "example.com"),
            Some(30)
        );
        assert_eq!(state.active_findings(), 0);
    }

    #[test]
    fn needs_investigation_keeps_active() {
        let mut state = SemanticState::new();
        let finding_id = Uuid::now_v7();
        state.add_finding_id(finding_id);

        let verdict = Verdict::new(
            finding_id,
            TriageVerdict::NeedsInvestigation,
            "agent-1",
            "unclear",
            0.5,
        );
        apply_verdict(&mut state, &verdict, &[]);

        assert_eq!(state.active_findings(), 1);
    }
}
