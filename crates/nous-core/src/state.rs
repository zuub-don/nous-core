//! Semantic state engine: rolling in-memory model of "what's happening right now."

use std::collections::HashMap;

use crate::entity::{Entity, EntityType};
use crate::event::NousEvent;

/// Rolling semantic state — a live situational model, not a log store.
#[derive(Debug, Default)]
pub struct SemanticState {
    /// Entity risk scores, keyed by (entity_type, value).
    entity_scores: HashMap<(EntityType, String), u8>,

    /// Total events ingested since last reset.
    event_count: u64,

    /// Events ingested per OCSF class_uid.
    class_counts: HashMap<u32, u64>,

    /// Active findings awaiting triage.
    active_findings: u64,
}

impl SemanticState {
    /// Create a new empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest an event into the semantic state.
    pub fn ingest(&mut self, event: &NousEvent) {
        self.event_count += 1;
        *self.class_counts.entry(event.class_uid).or_insert(0) += 1;
    }

    /// Update risk score for an entity.
    pub fn update_entity_risk(&mut self, entity: &Entity, score: u8) {
        let key = (entity.entity_type, entity.value.clone());
        self.entity_scores.insert(key, score);
    }

    /// Get risk score for an entity, if tracked.
    pub fn entity_risk(&self, entity_type: EntityType, value: &str) -> Option<u8> {
        self.entity_scores
            .get(&(entity_type, value.to_owned()))
            .copied()
    }

    /// Total events ingested.
    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Event count for a specific OCSF class.
    pub fn class_count(&self, class_uid: u32) -> u64 {
        self.class_counts.get(&class_uid).copied().unwrap_or(0)
    }

    /// Number of active findings awaiting triage.
    pub fn active_findings(&self) -> u64 {
        self.active_findings
    }

    /// Increment active finding count.
    pub fn add_finding(&mut self) {
        self.active_findings += 1;
    }

    /// Decrement active finding count (finding triaged).
    pub fn resolve_finding(&mut self) {
        self.active_findings = self.active_findings.saturating_sub(1);
    }

    /// Reset all counters (e.g., on window rotation).
    pub fn reset_counters(&mut self) {
        self.event_count = 0;
        self.class_counts.clear();
        self.active_findings = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::EntityType;
    use crate::event::*;
    use crate::severity::Severity;

    fn sample_event(class_uid: u32) -> NousEvent {
        NousEvent::new(
            1_000_000_000,
            class_uid,
            1,
            Severity::Info,
            EventSource {
                adapter: AdapterType::Suricata,
                product: None,
                sensor: None,
                original_id: None,
            },
            EventPayload::SystemLog(SystemLog {
                source_name: "test".into(),
                message: "test event".into(),
            }),
        )
    }

    #[test]
    fn state_ingestion_counts() {
        let mut state = SemanticState::new();
        assert_eq!(state.event_count(), 0);

        state.ingest(&sample_event(4003));
        state.ingest(&sample_event(4003));
        state.ingest(&sample_event(2004));

        assert_eq!(state.event_count(), 3);
        assert_eq!(state.class_count(4003), 2);
        assert_eq!(state.class_count(2004), 1);
        assert_eq!(state.class_count(9999), 0);
    }

    #[test]
    fn state_entity_risk_tracking() {
        let mut state = SemanticState::new();
        let entity = Entity::new(EntityType::Domain, "c2-beacon.xyz");

        state.update_entity_risk(&entity, 85);
        assert_eq!(
            state.entity_risk(EntityType::Domain, "c2-beacon.xyz"),
            Some(85)
        );
        assert_eq!(state.entity_risk(EntityType::Domain, "google.com"), None);
    }

    #[test]
    fn state_findings_lifecycle() {
        let mut state = SemanticState::new();
        assert_eq!(state.active_findings(), 0);

        state.add_finding();
        state.add_finding();
        assert_eq!(state.active_findings(), 2);

        state.resolve_finding();
        assert_eq!(state.active_findings(), 1);

        state.resolve_finding();
        state.resolve_finding(); // saturating
        assert_eq!(state.active_findings(), 0);
    }

    #[test]
    fn state_reset_counters() {
        let mut state = SemanticState::new();
        state.ingest(&sample_event(4003));
        state.add_finding();
        state.reset_counters();

        assert_eq!(state.event_count(), 0);
        assert_eq!(state.class_count(4003), 0);
        assert_eq!(state.active_findings(), 0);
    }
}
