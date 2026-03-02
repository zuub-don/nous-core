//! Semantic state engine: rolling in-memory model of "what's happening right now."

use std::collections::HashMap;

use uuid::Uuid;

use crate::entity::EntityType;
use crate::event::{
    Authentication, DetectionFinding, DnsActivity, EntityScore, EventPayload, HttpActivity,
    NetworkConnection, NousEvent, StateSnapshot, TlsActivity,
};

/// Metadata tracked per entity.
#[derive(Debug, Clone)]
pub struct EntityMeta {
    /// Current risk score (0-100).
    pub risk_score: u8,
    /// When this entity was first seen (epoch nanos).
    pub first_seen: i64,
    /// When this entity was last seen (epoch nanos).
    pub last_seen: i64,
    /// Total number of events referencing this entity.
    pub hit_count: u64,
}

/// Rolling semantic state — a live situational model, not a log store.
#[derive(Debug, Default)]
pub struct SemanticState {
    /// Entity metadata, keyed by (entity_type, value).
    entity_meta: HashMap<(EntityType, String), EntityMeta>,

    /// Total events ingested since last reset.
    event_count: u64,

    /// Events ingested per OCSF class_uid.
    class_counts: HashMap<u32, u64>,

    /// Active finding IDs awaiting triage.
    active_finding_ids: Vec<Uuid>,

    /// Severity distribution histogram: indices 0-5 map to Unknown..Critical.
    severity_histogram: [u64; 6],

    /// Suppression rules: rule_uid → suppress-until timestamp (epoch nanos).
    suppression_rules: HashMap<String, i64>,
}

impl SemanticState {
    /// Create a new empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest an event into the semantic state.
    ///
    /// Updates counters, severity histogram, and auto-extracts entities.
    pub fn ingest(&mut self, event: &NousEvent) {
        self.event_count += 1;
        *self.class_counts.entry(event.class_uid).or_insert(0) += 1;
        self.severity_histogram[event.severity.id() as usize] += 1;

        // Auto-extract entities and update metadata
        for (etype, val) in extract_entities(event) {
            let key = (etype, val);
            let meta = self.entity_meta.entry(key).or_insert_with(|| EntityMeta {
                risk_score: 0,
                first_seen: event.time,
                last_seen: event.time,
                hit_count: 0,
            });
            meta.last_seen = event.time;
            meta.hit_count += 1;
        }
    }

    /// Update risk score for an entity by type and value.
    pub fn update_entity_risk(&mut self, entity_type: EntityType, value: &str, score: u8) {
        let key = (entity_type, value.to_owned());
        let meta = self.entity_meta.entry(key).or_insert_with(|| {
            let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
            EntityMeta {
                risk_score: 0,
                first_seen: now,
                last_seen: now,
                hit_count: 0,
            }
        });
        meta.risk_score = score;
    }

    /// Adjust entity risk score by a signed delta, clamping to 0-100.
    pub fn adjust_entity_risk(&mut self, entity_type: EntityType, value: &str, delta: i16) {
        let key = (entity_type, value.to_owned());
        if let Some(meta) = self.entity_meta.get_mut(&key) {
            let new_score = (meta.risk_score as i16 + delta).clamp(0, 100) as u8;
            meta.risk_score = new_score;
        }
    }

    /// Get risk score for an entity, if tracked.
    pub fn entity_risk(&self, entity_type: EntityType, value: &str) -> Option<u8> {
        self.entity_meta
            .get(&(entity_type, value.to_owned()))
            .map(|m| m.risk_score)
    }

    /// Get full entity metadata, if tracked.
    pub fn entity_meta(&self, entity_type: EntityType, value: &str) -> Option<&EntityMeta> {
        self.entity_meta.get(&(entity_type, value.to_owned()))
    }

    /// Return top N entities sorted by risk score descending.
    pub fn top_entities(&self, n: usize) -> Vec<(&(EntityType, String), &EntityMeta)> {
        let mut entries: Vec<_> = self.entity_meta.iter().collect();
        entries.sort_by(|a, b| b.1.risk_score.cmp(&a.1.risk_score));
        entries.truncate(n);
        entries
    }

    /// Return top N OCSF classes sorted by count descending.
    pub fn top_classes(&self, n: usize) -> Vec<(u32, u64)> {
        let mut entries: Vec<_> = self.class_counts.iter().map(|(&k, &v)| (k, v)).collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(n);
        entries
    }

    /// Return the class counts map.
    pub fn class_counts(&self) -> &HashMap<u32, u64> {
        &self.class_counts
    }

    /// Total events ingested.
    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Event count for a specific OCSF class.
    pub fn class_count(&self, class_uid: u32) -> u64 {
        self.class_counts.get(&class_uid).copied().unwrap_or(0)
    }

    /// Return the severity histogram (indices 0-5).
    pub fn severity_histogram(&self) -> &[u64; 6] {
        &self.severity_histogram
    }

    /// Number of active findings awaiting triage.
    pub fn active_findings(&self) -> u64 {
        self.active_finding_ids.len() as u64
    }

    /// Return the list of active finding IDs.
    pub fn active_finding_ids(&self) -> &[Uuid] {
        &self.active_finding_ids
    }

    /// Add an active finding by ID.
    pub fn add_finding_id(&mut self, id: Uuid) {
        self.active_finding_ids.push(id);
    }

    /// Increment active finding count (backward compat wrapper).
    pub fn add_finding(&mut self) {
        self.add_finding_id(Uuid::now_v7());
    }

    /// Resolve a specific finding by ID.
    pub fn resolve_finding_id(&mut self, id: &Uuid) {
        self.active_finding_ids.retain(|fid| fid != id);
    }

    /// Decrement active finding count (finding triaged). Removes the oldest.
    pub fn resolve_finding(&mut self) {
        if !self.active_finding_ids.is_empty() {
            self.active_finding_ids.remove(0);
        }
    }

    /// Add a suppression rule.
    pub fn add_suppression(&mut self, rule_uid: String, suppress_until: i64) {
        self.suppression_rules.insert(rule_uid, suppress_until);
    }

    /// Check if a rule is currently suppressed.
    pub fn is_suppressed(&self, rule_uid: &str, now: i64) -> bool {
        self.suppression_rules
            .get(rule_uid)
            .is_some_and(|&until| now < until)
    }

    /// Number of tracked entities.
    pub fn entity_count(&self) -> usize {
        self.entity_meta.len()
    }

    /// Reset all counters (e.g., on window rotation).
    pub fn reset_counters(&mut self) {
        self.event_count = 0;
        self.class_counts.clear();
        self.active_finding_ids.clear();
        self.severity_histogram = [0; 6];
        self.suppression_rules.clear();
        self.entity_meta.clear();
    }

    /// Produce a state snapshot event payload.
    pub fn snapshot(&self) -> StateSnapshot {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        StateSnapshot {
            snapshot_time: now,
            event_count: self.event_count,
            active_findings: self.active_findings(),
            class_counts: self.top_classes(20),
            entity_scores: self
                .top_entities(20)
                .into_iter()
                .map(|((et, val), meta)| EntityScore {
                    entity_type: format!("{et:?}").to_lowercase(),
                    value: val.clone(),
                    score: meta.risk_score,
                })
                .collect(),
        }
    }
}

/// Extract entities from an event payload for automatic tracking.
pub fn extract_entities(event: &NousEvent) -> Vec<(EntityType, String)> {
    let mut entities = Vec::new();
    match &event.payload {
        EventPayload::DnsActivity(DnsActivity {
            src, dst, query, ..
        }) => {
            entities.push((EntityType::IpAddress, src.ip.to_string()));
            entities.push((EntityType::IpAddress, dst.ip.to_string()));
            if !query.hostname.is_empty() {
                entities.push((EntityType::Domain, query.hostname.clone()));
            }
        }
        EventPayload::NetworkConnection(NetworkConnection { src, dst, .. }) => {
            entities.push((EntityType::IpAddress, src.ip.to_string()));
            entities.push((EntityType::IpAddress, dst.ip.to_string()));
        }
        EventPayload::DetectionFinding(DetectionFinding { entities: ents, .. }) => {
            for e in ents {
                entities.push((e.entity_type, e.value.clone()));
            }
        }
        EventPayload::HttpActivity(HttpActivity { src, dst, .. }) => {
            entities.push((EntityType::IpAddress, src.ip.to_string()));
            entities.push((EntityType::IpAddress, dst.ip.to_string()));
        }
        EventPayload::TlsActivity(TlsActivity {
            src,
            dst,
            server_name,
            ..
        }) => {
            entities.push((EntityType::IpAddress, src.ip.to_string()));
            entities.push((EntityType::IpAddress, dst.ip.to_string()));
            if let Some(sni) = server_name {
                entities.push((EntityType::Domain, sni.clone()));
            }
        }
        EventPayload::Authentication(Authentication { user, src, .. }) => {
            entities.push((EntityType::User, user.clone()));
            if let Some(ep) = src {
                entities.push((EntityType::IpAddress, ep.ip.to_string()));
            }
        }
        _ => {}
    }
    entities
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

    fn sample_dns_event() -> NousEvent {
        NousEvent::new(
            1_000_000_000,
            4003,
            4,
            Severity::Info,
            EventSource {
                adapter: AdapterType::Suricata,
                product: None,
                sensor: None,
                original_id: None,
            },
            EventPayload::DnsActivity(DnsActivity {
                activity_id: 1,
                query: DnsQuery {
                    hostname: "evil.com".into(),
                    type_id: 1,
                    class: 1,
                    transaction_uid: None,
                },
                response: None,
                src: Endpoint {
                    ip: "10.0.0.1".parse().unwrap(),
                    port: Some(54321),
                    hostname: None,
                    mac: None,
                },
                dst: Endpoint {
                    ip: "8.8.8.8".parse().unwrap(),
                    port: Some(53),
                    hostname: None,
                    mac: None,
                },
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
        state.update_entity_risk(EntityType::Domain, "c2-beacon.xyz", 85);
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
    fn state_finding_ids() {
        let mut state = SemanticState::new();
        let id1 = Uuid::now_v7();
        let id2 = Uuid::now_v7();
        state.add_finding_id(id1);
        state.add_finding_id(id2);
        assert_eq!(state.active_finding_ids().len(), 2);

        state.resolve_finding_id(&id1);
        assert_eq!(state.active_finding_ids().len(), 1);
        assert_eq!(state.active_finding_ids()[0], id2);
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
        assert_eq!(state.severity_histogram(), &[0; 6]);
    }

    #[test]
    fn severity_histogram_populated() {
        let mut state = SemanticState::new();
        let mut evt = sample_event(4003);
        evt.severity = Severity::Info;
        state.ingest(&evt);
        evt.severity = Severity::High;
        state.ingest(&evt);
        evt.severity = Severity::High;
        state.ingest(&evt);
        evt.severity = Severity::Critical;
        state.ingest(&evt);

        let hist = state.severity_histogram();
        assert_eq!(hist[1], 1); // Info
        assert_eq!(hist[4], 2); // High
        assert_eq!(hist[5], 1); // Critical
    }

    #[test]
    fn top_entities_ordering() {
        let mut state = SemanticState::new();
        state.update_entity_risk(EntityType::IpAddress, "10.0.0.1", 90);
        state.update_entity_risk(EntityType::IpAddress, "10.0.0.2", 50);
        state.update_entity_risk(EntityType::Domain, "evil.com", 95);

        let top = state.top_entities(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].1.risk_score, 95);
        assert_eq!(top[1].1.risk_score, 90);
    }

    #[test]
    fn top_classes_ordering() {
        let mut state = SemanticState::new();
        for _ in 0..5 {
            state.ingest(&sample_event(4003));
        }
        for _ in 0..10 {
            state.ingest(&sample_event(2004));
        }
        state.ingest(&sample_event(4001));

        let top = state.top_classes(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0], (2004, 10));
        assert_eq!(top[1], (4003, 5));
    }

    #[test]
    fn entity_auto_extraction_dns() {
        let mut state = SemanticState::new();
        state.ingest(&sample_dns_event());

        assert!(state
            .entity_meta(EntityType::IpAddress, "10.0.0.1")
            .is_some());
        assert!(state
            .entity_meta(EntityType::IpAddress, "8.8.8.8")
            .is_some());
        assert!(state.entity_meta(EntityType::Domain, "evil.com").is_some());
    }

    #[test]
    fn entity_first_seen_last_seen_hit_count() {
        let mut state = SemanticState::new();
        let mut evt = sample_dns_event();
        evt.time = 1000;
        state.ingest(&evt);
        evt.time = 2000;
        state.ingest(&evt);

        let meta = state.entity_meta(EntityType::Domain, "evil.com").unwrap();
        assert_eq!(meta.first_seen, 1000);
        assert_eq!(meta.last_seen, 2000);
        assert_eq!(meta.hit_count, 2);
    }

    #[test]
    fn suppression_add_and_check() {
        let mut state = SemanticState::new();
        state.add_suppression("rule-1".into(), 5000);

        assert!(state.is_suppressed("rule-1", 4000));
        assert!(!state.is_suppressed("rule-1", 6000));
        assert!(!state.is_suppressed("rule-2", 4000));
    }

    #[test]
    fn adjust_entity_risk_clamps() {
        let mut state = SemanticState::new();
        state.update_entity_risk(EntityType::IpAddress, "10.0.0.1", 50);

        state.adjust_entity_risk(EntityType::IpAddress, "10.0.0.1", 60);
        assert_eq!(
            state.entity_risk(EntityType::IpAddress, "10.0.0.1"),
            Some(100)
        );

        state.adjust_entity_risk(EntityType::IpAddress, "10.0.0.1", -200);
        assert_eq!(
            state.entity_risk(EntityType::IpAddress, "10.0.0.1"),
            Some(0)
        );
    }

    #[test]
    fn snapshot_produces_valid_data() {
        let mut state = SemanticState::new();
        state.ingest(&sample_dns_event());
        state.update_entity_risk(EntityType::Domain, "evil.com", 80);
        state.add_finding();

        let snap = state.snapshot();
        assert_eq!(snap.event_count, 1);
        assert_eq!(snap.active_findings, 1);
        assert!(!snap.class_counts.is_empty());
        assert!(!snap.entity_scores.is_empty());
    }
}
