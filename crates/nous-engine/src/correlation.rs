//! Correlation engine: sliding-window rule evaluation over the event stream.
//!
//! Subscribes to the EventBus, maintains a time-bounded window of events,
//! runs correlation rules, and produces `CorrelationFinding` events (class_uid 2001).

use std::collections::{HashMap, VecDeque};

use nous_core::entity::Entity;
use nous_core::event::{
    AdapterType, AttackMapping, CorrelationFinding, CorrelationRuleId, DetectionFinding,
    DnsActivity, EventPayload, EventSource, FindingStatus, NousEvent, RiskLevel,
};
use nous_core::severity::Severity;

/// Default correlation window: 5 minutes in nanoseconds.
const DEFAULT_WINDOW_NANOS: i64 = 300_000_000_000;

/// Minimum DetectionFindings sharing an entity to trigger the entity cluster rule.
const ENTITY_CLUSTER_THRESHOLD: usize = 3;

/// Minimum DNS queries from a single source IP to trigger the high-frequency DNS rule.
const DNS_FREQ_THRESHOLD: usize = 50;

/// Correlation engine that evaluates rules over a sliding time window.
pub struct CorrelationEngine {
    /// Sliding window of recent events.
    window: VecDeque<NousEvent>,
    /// Window duration in nanoseconds.
    window_nanos: i64,
    /// Deduplication: fingerprint → expiry timestamp (epoch nanos).
    fingerprints: HashMap<u64, i64>,
}

impl CorrelationEngine {
    /// Create a new correlation engine with the given window duration in seconds.
    pub fn new(window_secs: u64) -> Self {
        Self {
            window: VecDeque::new(),
            window_nanos: (window_secs as i64) * 1_000_000_000,
            fingerprints: HashMap::new(),
        }
    }

    /// Process an incoming event: prune the window, run rules, return any findings.
    pub fn process(&mut self, event: NousEvent) -> Vec<NousEvent> {
        // Feedback loop guard: skip correlation findings to prevent infinite loops.
        if event.class_uid == 2001 {
            return Vec::new();
        }

        let now = event.time;
        self.prune_window(now);
        self.prune_fingerprints(now);
        self.window.push_back(event);

        let mut findings = Vec::new();
        findings.extend(self.run_entity_cluster_rule(now));
        findings.extend(self.run_high_frequency_dns_rule(now));
        findings
    }

    /// Remove events outside the window.
    fn prune_window(&mut self, now: i64) {
        let cutoff = now - self.window_nanos;
        while self.window.front().is_some_and(|e| e.time < cutoff) {
            self.window.pop_front();
        }
    }

    /// Remove expired fingerprints.
    fn prune_fingerprints(&mut self, now: i64) {
        self.fingerprints.retain(|_, expiry| *expiry > now);
    }

    /// Compute a deterministic fingerprint for deduplication.
    fn fingerprint(rule: &CorrelationRuleId, entity_keys: &mut [String]) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        rule.hash(&mut hasher);
        entity_keys.sort();
        for k in entity_keys.iter() {
            k.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Check if a fingerprint is already active (deduplicated).
    fn is_duplicate(&mut self, fp: u64, expiry: i64) -> bool {
        if self.fingerprints.contains_key(&fp) {
            return true;
        }
        self.fingerprints.insert(fp, expiry);
        false
    }

    /// Entity cluster rule: 3+ DetectionFindings sharing any entity within the window.
    fn run_entity_cluster_rule(&mut self, now: i64) -> Vec<NousEvent> {
        // Build entity → list of event indices for DetectionFindings (owned keys)
        let mut entity_events: HashMap<(nous_core::entity::EntityType, String), Vec<usize>> =
            HashMap::new();

        for (idx, evt) in self.window.iter().enumerate() {
            if let EventPayload::DetectionFinding(DetectionFinding { entities: ents, .. }) =
                &evt.payload
            {
                for e in ents {
                    entity_events
                        .entry((e.entity_type, e.value.clone()))
                        .or_default()
                        .push(idx);
                }
            }
        }

        let mut findings = Vec::new();

        for ((etype, eval), indices) in &entity_events {
            if indices.len() < ENTITY_CLUSTER_THRESHOLD {
                continue;
            }

            let entity = Entity::new(*etype, eval.clone());
            let mut entity_keys = vec![format!("{etype:?}:{eval}")];
            let rule_id = CorrelationRuleId::EntityCluster;
            let fp = Self::fingerprint(&rule_id, &mut entity_keys);
            let expiry = now + self.window_nanos;

            if self.is_duplicate(fp, expiry) {
                continue;
            }

            let source_ids: Vec<uuid::Uuid> = indices.iter().map(|&i| self.window[i].id).collect();
            let signal_count = indices.len() as u32;
            let window_start = self.window[*indices.first().expect("non-empty")].time;
            let window_end = now;

            let risk_score = (50 + signal_count * 10).min(100) as u8;
            let risk_level = if risk_score >= 80 {
                RiskLevel::High
            } else {
                RiskLevel::Medium
            };

            let cf = CorrelationFinding {
                title: format!(
                    "Entity cluster: {} findings share {eval}",
                    signal_count
                ),
                description: format!(
                    "{signal_count} DetectionFindings reference entity {etype:?}={eval} within the correlation window"
                ),
                rule_id,
                entities: vec![entity],
                source_event_ids: source_ids,
                signal_count,
                window_start,
                window_end,
                risk_score,
                risk_level,
                status: FindingStatus::New,
                attack: None,
            };

            findings.push(NousEvent::new(
                now,
                2001,
                2,
                Severity::High,
                EventSource {
                    adapter: AdapterType::NousInternal,
                    product: Some("nous-correlation".into()),
                    sensor: None,
                    original_id: None,
                },
                EventPayload::CorrelationFinding(cf),
            ));
        }

        findings
    }

    /// High-frequency DNS rule: 50+ DNS queries from a single source IP within the window.
    fn run_high_frequency_dns_rule(&mut self, now: i64) -> Vec<NousEvent> {
        let mut src_counts: HashMap<String, Vec<usize>> = HashMap::new();

        for (idx, evt) in self.window.iter().enumerate() {
            if let EventPayload::DnsActivity(DnsActivity { src, .. }) = &evt.payload {
                src_counts.entry(src.ip.to_string()).or_default().push(idx);
            }
        }

        let mut findings = Vec::new();

        for (src_ip, indices) in &src_counts {
            if indices.len() < DNS_FREQ_THRESHOLD {
                continue;
            }

            let entity = Entity::new(nous_core::entity::EntityType::IpAddress, src_ip.clone());
            let mut entity_keys = vec![format!("ip:{src_ip}")];
            let rule_id = CorrelationRuleId::HighFrequencyDns;
            let fp = Self::fingerprint(&rule_id, &mut entity_keys);
            let expiry = now + self.window_nanos;

            if self.is_duplicate(fp, expiry) {
                continue;
            }

            let source_ids: Vec<uuid::Uuid> = indices.iter().map(|&i| self.window[i].id).collect();
            let signal_count = indices.len() as u32;
            let window_start = self.window[*indices.first().expect("non-empty")].time;
            let window_end = now;

            let risk_score = (60 + (signal_count / 10) * 5).min(100) as u8;
            let risk_level = if risk_score >= 80 {
                RiskLevel::High
            } else {
                RiskLevel::Medium
            };

            let cf = CorrelationFinding {
                title: format!(
                    "High-frequency DNS: {signal_count} queries from {src_ip}"
                ),
                description: format!(
                    "{signal_count} DNS queries from {src_ip} within the correlation window — potential tunneling/DGA"
                ),
                rule_id,
                entities: vec![entity],
                source_event_ids: source_ids,
                signal_count,
                window_start,
                window_end,
                risk_score,
                risk_level,
                status: FindingStatus::New,
                attack: Some(AttackMapping {
                    technique_id: "T1071.004".into(),
                    technique_name: "Application Layer Protocol: DNS".into(),
                    tactic: "command-and-control".into(),
                }),
            };

            findings.push(NousEvent::new(
                now,
                2001,
                2,
                Severity::High,
                EventSource {
                    adapter: AdapterType::NousInternal,
                    product: Some("nous-correlation".into()),
                    sensor: None,
                    original_id: None,
                },
                EventPayload::CorrelationFinding(cf),
            ));
        }

        findings
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new((DEFAULT_WINDOW_NANOS / 1_000_000_000) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use nous_core::entity::{Entity, EntityType};
    use nous_core::event::*;
    use nous_core::severity::Severity;

    fn make_detection_finding(time: i64, entities: Vec<Entity>) -> NousEvent {
        NousEvent {
            id: uuid::Uuid::now_v7(),
            time,
            ingest_time: time,
            class_uid: 2004,
            category_uid: 2,
            severity: Severity::High,
            source: EventSource {
                adapter: AdapterType::Suricata,
                product: None,
                sensor: None,
                original_id: None,
            },
            payload: EventPayload::DetectionFinding(DetectionFinding {
                title: "test finding".into(),
                description: None,
                risk_score: 70,
                risk_level: RiskLevel::High,
                rule: None,
                entities,
                status: FindingStatus::New,
                attack: None,
            }),
            raw: None,
        }
    }

    fn make_dns_event(time: i64, src_ip: std::net::IpAddr) -> NousEvent {
        NousEvent {
            id: uuid::Uuid::now_v7(),
            time,
            ingest_time: time,
            class_uid: 4003,
            category_uid: 4,
            severity: Severity::Info,
            source: EventSource {
                adapter: AdapterType::Suricata,
                product: None,
                sensor: None,
                original_id: None,
            },
            payload: EventPayload::DnsActivity(DnsActivity {
                activity_id: 1,
                query: DnsQuery {
                    hostname: "example.com".into(),
                    type_id: 1,
                    class: 1,
                    transaction_uid: None,
                },
                response: None,
                src: Endpoint {
                    ip: src_ip,
                    port: Some(54321),
                    hostname: None,
                    mac: None,
                },
                dst: Endpoint {
                    ip: std::net::IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                    port: Some(53),
                    hostname: None,
                    mac: None,
                },
            }),
            raw: None,
        }
    }

    #[test]
    fn entity_cluster_fires_at_threshold() {
        let mut engine = CorrelationEngine::new(300);
        let entity = Entity::new(EntityType::IpAddress, "10.0.0.1");
        let base_time = 1_000_000_000_000i64;

        // Feed 2 findings — should not fire
        for i in 0..2 {
            let findings = engine.process(make_detection_finding(
                base_time + i * 1_000_000_000,
                vec![entity.clone()],
            ));
            assert!(findings.is_empty(), "should not fire below threshold");
        }

        // 3rd finding triggers the rule
        let findings = engine.process(make_detection_finding(
            base_time + 2 * 1_000_000_000,
            vec![entity.clone()],
        ));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].class_uid, 2001);
        match &findings[0].payload {
            EventPayload::CorrelationFinding(cf) => {
                assert_eq!(cf.rule_id, CorrelationRuleId::EntityCluster);
                assert_eq!(cf.signal_count, 3);
                assert!(cf.title.contains("10.0.0.1"));
            }
            _ => panic!("expected CorrelationFinding"),
        }
    }

    #[test]
    fn entity_cluster_below_threshold_no_fire() {
        let mut engine = CorrelationEngine::new(300);
        let entity = Entity::new(EntityType::IpAddress, "10.0.0.1");
        let base_time = 1_000_000_000_000i64;

        for i in 0..2 {
            let findings = engine.process(make_detection_finding(
                base_time + i * 1_000_000_000,
                vec![entity.clone()],
            ));
            assert!(findings.is_empty());
        }
    }

    #[test]
    fn entity_cluster_deduplication() {
        let mut engine = CorrelationEngine::new(300);
        let entity = Entity::new(EntityType::IpAddress, "10.0.0.1");
        let base_time = 1_000_000_000_000i64;

        // Feed 3 findings to trigger
        for i in 0..3 {
            engine.process(make_detection_finding(
                base_time + i * 1_000_000_000,
                vec![entity.clone()],
            ));
        }

        // 4th finding should NOT produce a duplicate
        let findings = engine.process(make_detection_finding(
            base_time + 3 * 1_000_000_000,
            vec![entity.clone()],
        ));
        assert!(findings.is_empty(), "duplicate should be suppressed");
    }

    #[test]
    fn window_expiry_clears_events() {
        let mut engine = CorrelationEngine::new(10); // 10 second window
        let entity = Entity::new(EntityType::IpAddress, "10.0.0.1");
        let base_time = 1_000_000_000_000i64;

        // Feed 2 findings at time 0
        for i in 0..2 {
            engine.process(make_detection_finding(
                base_time + i * 1_000_000_000,
                vec![entity.clone()],
            ));
        }

        // Feed 1 finding 20 seconds later — previous events should be expired
        let findings = engine.process(make_detection_finding(
            base_time + 20 * 1_000_000_000,
            vec![entity.clone()],
        ));
        assert!(findings.is_empty(), "old events should have expired");
    }

    #[test]
    fn dns_frequency_fires_at_threshold() {
        let mut engine = CorrelationEngine::new(300);
        let src_ip = std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let base_time = 1_000_000_000_000i64;

        // Feed 49 DNS events — no fire
        for i in 0..49 {
            let findings = engine.process(make_dns_event(base_time + i * 100_000_000, src_ip));
            assert!(findings.is_empty());
        }

        // 50th triggers
        let findings = engine.process(make_dns_event(base_time + 49 * 100_000_000, src_ip));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].class_uid, 2001);
        match &findings[0].payload {
            EventPayload::CorrelationFinding(cf) => {
                assert_eq!(cf.rule_id, CorrelationRuleId::HighFrequencyDns);
                assert_eq!(cf.signal_count, 50);
                assert!(cf.attack.is_some());
                assert_eq!(cf.attack.as_ref().unwrap().technique_id, "T1071.004");
            }
            _ => panic!("expected CorrelationFinding"),
        }
    }

    #[test]
    fn dns_frequency_below_threshold_no_fire() {
        let mut engine = CorrelationEngine::new(300);
        let src_ip = std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let base_time = 1_000_000_000_000i64;

        for i in 0..10 {
            let findings = engine.process(make_dns_event(base_time + i * 100_000_000, src_ip));
            assert!(findings.is_empty());
        }
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let rule = CorrelationRuleId::EntityCluster;
        let mut keys1 = vec!["ip:10.0.0.1".to_string(), "domain:evil.com".to_string()];
        let mut keys2 = vec!["domain:evil.com".to_string(), "ip:10.0.0.1".to_string()];

        let fp1 = CorrelationEngine::fingerprint(&rule, &mut keys1);
        let fp2 = CorrelationEngine::fingerprint(&rule, &mut keys2);
        assert_eq!(fp1, fp2, "fingerprint should be order-independent");
    }

    #[test]
    fn feedback_loop_guard_skips_class_2001() {
        let mut engine = CorrelationEngine::new(300);

        // Create a class 2001 event
        let evt = NousEvent::new(
            1_000_000_000_000,
            2001,
            2,
            Severity::High,
            EventSource {
                adapter: AdapterType::NousInternal,
                product: None,
                sensor: None,
                original_id: None,
            },
            EventPayload::CorrelationFinding(CorrelationFinding {
                title: "test".into(),
                description: "test".into(),
                rule_id: CorrelationRuleId::EntityCluster,
                entities: vec![],
                source_event_ids: vec![],
                signal_count: 0,
                window_start: 0,
                window_end: 0,
                risk_score: 0,
                risk_level: RiskLevel::Info,
                status: FindingStatus::New,
                attack: None,
            }),
        );

        let findings = engine.process(evt);
        assert!(findings.is_empty());
        assert!(
            engine.window.is_empty(),
            "class 2001 events should not enter the window"
        );
    }

    #[test]
    fn correct_envelope_fields() {
        let mut engine = CorrelationEngine::new(300);
        let entity = Entity::new(EntityType::IpAddress, "10.0.0.1");
        let base_time = 1_000_000_000_000i64;

        for i in 0..3 {
            engine.process(make_detection_finding(
                base_time + i * 1_000_000_000,
                vec![entity.clone()],
            ));
        }

        // Get the findings from the 3rd event
        let mut engine2 = CorrelationEngine::new(300);
        for i in 0..2 {
            engine2.process(make_detection_finding(
                base_time + i * 1_000_000_000,
                vec![entity.clone()],
            ));
        }
        let findings = engine2.process(make_detection_finding(
            base_time + 2 * 1_000_000_000,
            vec![entity.clone()],
        ));

        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.class_uid, 2001);
        assert_eq!(f.category_uid, 2);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.source.adapter, AdapterType::NousInternal);
        assert!(!f.id.is_nil());
    }
}
