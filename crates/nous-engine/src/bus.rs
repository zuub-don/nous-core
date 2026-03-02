//! Event bus: broadcast channel for distributing events to multiple consumers.

use nous_core::event::NousEvent;
use tokio::sync::broadcast;

/// Event bus backed by a tokio broadcast channel.
#[derive(Debug, Clone)]
pub struct EventBus {
    sender: broadcast::Sender<NousEvent>,
}

impl EventBus {
    /// Create a new event bus with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Publish an event to all subscribers.
    pub fn publish(&self, event: NousEvent) -> usize {
        // send returns Err only if there are no receivers; that's fine
        self.sender.send(event).unwrap_or(0)
    }

    /// Subscribe to the event stream.
    pub fn subscribe(&self) -> broadcast::Receiver<NousEvent> {
        self.sender.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nous_core::event::*;
    use nous_core::severity::Severity;

    fn sample_event() -> NousEvent {
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

    #[tokio::test]
    async fn publish_and_subscribe() {
        let bus = EventBus::new(100);
        let mut rx = bus.subscribe();

        let evt = sample_event();
        let class_uid = evt.class_uid;
        bus.publish(evt);

        let received = rx.recv().await.unwrap();
        assert_eq!(received.class_uid, class_uid);
    }

    #[tokio::test]
    async fn multiple_subscribers() {
        let bus = EventBus::new(100);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        bus.publish(sample_event());

        let r1 = rx1.recv().await.unwrap();
        let r2 = rx2.recv().await.unwrap();
        assert_eq!(r1.class_uid, r2.class_uid);
    }

    #[test]
    fn publish_no_subscribers() {
        let bus = EventBus::new(100);
        // Should not panic
        let count = bus.publish(sample_event());
        assert_eq!(count, 0);
    }
}
