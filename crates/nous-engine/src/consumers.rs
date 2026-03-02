//! Event bus consumers: state ingestion, NDJSON emission, and correlation.

use tracing::{debug, info, warn};

use crate::bus::EventBus;
use crate::correlation::CorrelationEngine;
use crate::state_store::SharedState;

/// Consume events from the bus and ingest into shared state.
pub async fn state_consumer(bus: &EventBus, shared: SharedState) {
    let mut rx = bus.subscribe();

    loop {
        match rx.recv().await {
            Ok(event) => match shared.write() {
                Ok(mut store) => {
                    store.ingest(event);
                    debug!(
                        count = store.state.event_count(),
                        "state consumer: ingested"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "state consumer: lock poisoned");
                    break;
                }
            },
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                warn!(skipped = n, "state consumer: lagged behind");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                debug!("state consumer: bus closed");
                break;
            }
        }
    }
}

/// Consume events from the bus and emit as NDJSON to stdout.
pub async fn ndjson_emitter(bus: &EventBus) {
    let mut rx = bus.subscribe();

    loop {
        match rx.recv().await {
            Ok(event) => {
                if let Ok(json) = serde_json::to_string(&event) {
                    println!("{json}");
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                warn!(skipped = n, "ndjson emitter: lagged behind");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                debug!("ndjson emitter: bus closed");
                break;
            }
        }
    }
}

/// Consume events from the bus, run correlation rules, and publish findings back.
pub async fn correlation_consumer(bus: &EventBus, window_secs: u64) {
    let mut rx = bus.subscribe();
    let mut engine = CorrelationEngine::new(window_secs);

    loop {
        match rx.recv().await {
            Ok(event) => {
                let findings = engine.process(event);
                for finding in findings {
                    info!(
                        class_uid = finding.class_uid,
                        "correlation consumer: publishing finding"
                    );
                    bus.publish(finding);
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                warn!(skipped = n, "correlation consumer: lagged behind");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                debug!("correlation consumer: bus closed");
                break;
            }
        }
    }
}

/// Consume events from the bus and persist to PostgreSQL.
#[cfg(feature = "persistence")]
pub async fn persistence_consumer(bus: &EventBus, pool: sqlx::PgPool) {
    let mut rx = bus.subscribe();

    loop {
        match rx.recv().await {
            Ok(event) => {
                if let Err(e) = crate::persistence::store_event(&pool, &event).await {
                    warn!(error = %e, "persistence consumer: failed to store event");
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                warn!(skipped = n, "persistence consumer: lagged behind");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                debug!("persistence consumer: bus closed");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_store::new_shared_state;
    use nous_core::event::*;
    use nous_core::severity::Severity;

    fn sample_event() -> nous_core::event::NousEvent {
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
            EventPayload::SystemLog(SystemLog {
                source_name: "test".into(),
                message: "test".into(),
            }),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn state_consumer_ingests() {
        let bus = EventBus::new(100);
        let shared = new_shared_state(100);

        let consumer_shared = shared.clone();
        let consumer_bus = bus.clone();
        let handle = tokio::spawn(async move {
            state_consumer(&consumer_bus, consumer_shared).await;
        });

        // Give consumer time to start and subscribe to the bus
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        bus.publish(sample_event());
        bus.publish(sample_event());

        // Give consumer time to process events
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let store = shared.read().unwrap();
        assert_eq!(store.state.event_count(), 2);

        handle.abort();
    }
}
