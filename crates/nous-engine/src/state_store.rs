//! Shared state store: semantic state + recent event buffer.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use nous_core::event::NousEvent;
use nous_core::state::SemanticState;
use nous_core::verdict::Verdict;

/// Thread-safe shared state accessed by both ingestion and gRPC layers.
pub type SharedState = Arc<RwLock<StateStore>>;

/// In-memory state store combining semantic state with a recent event buffer.
pub struct StateStore {
    /// Rolling semantic state.
    pub state: SemanticState,
    /// Bounded ring buffer of recent events.
    events: VecDeque<NousEvent>,
    /// Maximum number of events to retain.
    capacity: usize,
    /// Verdict history.
    verdicts: Vec<Verdict>,
}

impl StateStore {
    /// Create a new state store with the given event buffer capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            state: SemanticState::new(),
            events: VecDeque::with_capacity(capacity),
            capacity,
            verdicts: Vec::new(),
        }
    }

    /// Ingest an event: update semantic state and buffer the event.
    pub fn ingest(&mut self, event: NousEvent) {
        self.state.ingest(&event);

        // Track findings by ID
        if event.class_uid == 2004 {
            self.state.add_finding_id(event.id);
        }

        // Buffer event, evicting oldest if at capacity
        if self.events.len() >= self.capacity {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    /// Query recent events with optional filters.
    pub fn query_events(
        &self,
        class_uid: Option<u32>,
        min_severity: Option<u8>,
        limit: usize,
    ) -> Vec<&NousEvent> {
        self.events
            .iter()
            .rev()
            .filter(|e| class_uid.map_or(true, |c| e.class_uid == c))
            .filter(|e| min_severity.map_or(true, |s| e.severity.id() >= s))
            .take(limit)
            .collect()
    }

    /// Return a slice of the most recent events for context generation.
    pub fn recent_events_slice(&self, n: usize) -> Vec<&NousEvent> {
        self.events.iter().rev().take(n).collect()
    }

    /// Store a verdict.
    pub fn store_verdict(&mut self, verdict: Verdict) {
        self.verdicts.push(verdict);
    }

    /// Get verdict history.
    #[allow(dead_code)]
    pub fn verdicts(&self) -> &[Verdict] {
        &self.verdicts
    }

    /// Total number of buffered events.
    #[cfg(test)]
    pub fn buffered_count(&self) -> usize {
        self.events.len()
    }
}

/// Create a new shared state store.
pub fn new_shared_state(capacity: usize) -> SharedState {
    Arc::new(RwLock::new(StateStore::new(capacity)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nous_core::event::*;
    use nous_core::severity::Severity;

    fn sample_event(class_uid: u32, severity: Severity) -> NousEvent {
        NousEvent::new(
            1_000_000_000,
            class_uid,
            1,
            severity,
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
    fn ingest_and_query() {
        let mut store = StateStore::new(100);

        store.ingest(sample_event(4003, Severity::Info));
        store.ingest(sample_event(2004, Severity::High));
        store.ingest(sample_event(4001, Severity::Low));

        assert_eq!(store.state.event_count(), 3);
        assert_eq!(store.buffered_count(), 3);

        // Query all
        let events = store.query_events(None, None, 10);
        assert_eq!(events.len(), 3);

        // Filter by class
        let dns_events = store.query_events(Some(4003), None, 10);
        assert_eq!(dns_events.len(), 1);
        assert_eq!(dns_events[0].class_uid, 4003);

        // Filter by severity
        let high_events = store.query_events(None, Some(4), 10);
        assert_eq!(high_events.len(), 1);
    }

    #[test]
    fn buffer_eviction() {
        let mut store = StateStore::new(3);

        store.ingest(sample_event(1, Severity::Info));
        store.ingest(sample_event(2, Severity::Info));
        store.ingest(sample_event(3, Severity::Info));
        assert_eq!(store.buffered_count(), 3);

        // Fourth event should evict the first
        store.ingest(sample_event(4, Severity::Info));
        assert_eq!(store.buffered_count(), 3);

        let events = store.query_events(None, None, 10);
        // Most recent first
        assert_eq!(events[0].class_uid, 4);
        assert_eq!(events[2].class_uid, 2);

        // Semantic state still counts all ingested events
        assert_eq!(store.state.event_count(), 4);
    }

    #[test]
    fn finding_tracking() {
        let mut store = StateStore::new(100);
        store.ingest(sample_event(2004, Severity::High));
        store.ingest(sample_event(2004, Severity::Medium));
        assert_eq!(store.state.active_findings(), 2);
    }

    #[test]
    fn query_with_limit() {
        let mut store = StateStore::new(100);
        for _ in 0..10 {
            store.ingest(sample_event(4003, Severity::Info));
        }
        let events = store.query_events(None, None, 3);
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn recent_events_slice_returns_most_recent() {
        let mut store = StateStore::new(100);
        for i in 0..5 {
            store.ingest(sample_event(i, Severity::Info));
        }
        let recent = store.recent_events_slice(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].class_uid, 4); // most recent first
    }

    #[test]
    fn verdict_storage() {
        let mut store = StateStore::new(100);
        let v = nous_core::verdict::Verdict::new(
            uuid::Uuid::now_v7(),
            nous_core::verdict::TriageVerdict::TruePositive,
            "agent-1",
            "test",
            0.9,
        );
        store.store_verdict(v);
        assert_eq!(store.verdicts().len(), 1);
    }
}
