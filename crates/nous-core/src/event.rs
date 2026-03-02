use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entity::Entity;
use crate::severity::Severity;

/// Universal event envelope. Every event flowing through Nous Core
/// is wrapped in this structure regardless of source or class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NousEvent {
    /// Unique event identifier (UUIDv7 for time-ordered uniqueness).
    pub id: Uuid,

    /// Nanosecond-precision timestamp of when the event occurred at source.
    pub time: i64,

    /// Nanosecond-precision timestamp of when Nous Core ingested the event.
    pub ingest_time: i64,

    /// OCSF event class identifier.
    pub class_uid: u32,

    /// OCSF category identifier.
    pub category_uid: u16,

    /// Severity level.
    pub severity: Severity,

    /// Source adapter that produced this event.
    pub source: EventSource,

    /// The typed event payload.
    pub payload: EventPayload,
}

impl NousEvent {
    /// Create a new event with current ingest timestamp and a fresh UUIDv7.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        time: i64,
        class_uid: u32,
        category_uid: u16,
        severity: Severity,
        source: EventSource,
        payload: EventPayload,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            time,
            ingest_time: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            class_uid,
            category_uid,
            severity,
            source,
            payload,
        }
    }
}

/// Identifies the origin of an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSource {
    /// Adapter type (e.g., "suricata", "zeek", "syslog").
    pub adapter: AdapterType,

    /// Tool name and version (e.g., "Suricata 7.0.3").
    pub product: Option<String>,

    /// Hostname or sensor ID where the event was generated.
    pub sensor: Option<String>,

    /// Original event ID from the source tool (for dedup and correlation).
    pub original_id: Option<String>,
}

/// Adapter type discriminant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterType {
    Suricata,
    Zeek,
    Syslog,
    Journald,
    OcsfNative,
    NousInternal,
    Custom(String),
}

/// Typed event payloads covering all OCSF classes Nous Core handles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EventPayload {
    DnsActivity(DnsActivity),
    NetworkConnection(NetworkConnection),
    DetectionFinding(DetectionFinding),
    SystemLog(SystemLog),
}

/// OCSF class_uid: 4003 (DNS Activity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsActivity {
    pub activity_id: u8,
    pub query: DnsQuery,
    pub response: Option<DnsResponse>,
    pub src: Endpoint,
    pub dst: Endpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub hostname: String,
    pub type_id: u16,
    pub class: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResponse {
    pub rcode_id: u8,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub type_id: u16,
    pub rdata: String,
    pub ttl: u32,
}

/// OCSF class_uid: 4001 (Network Connection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub src: Endpoint,
    pub dst: Endpoint,
    pub protocol_id: u8,
    pub bytes_out: Option<u64>,
    pub bytes_in: Option<u64>,
    pub duration_us: Option<u64>,
}

/// OCSF class_uid: 2004 (Detection Finding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionFinding {
    pub title: String,
    pub description: Option<String>,
    pub risk_score: u8,
    pub risk_level: RiskLevel,
    pub rule: Option<DetectionRule>,
    pub entities: Vec<Entity>,
    pub status: FindingStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub uid: String,
    pub name: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    New,
    InProgress,
    Resolved,
    Suppressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Generic system log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemLog {
    pub source_name: String,
    pub message: String,
}

/// A network endpoint (host + port).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub hostname: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn event_creation_assigns_uuid_and_ingest_time() {
        let evt = NousEvent::new(
            1_000_000_000,
            4003,
            4,
            Severity::Info,
            EventSource {
                adapter: AdapterType::Suricata,
                product: Some("Suricata 7.0.3".into()),
                sensor: None,
                original_id: None,
            },
            EventPayload::DnsActivity(DnsActivity {
                activity_id: 1,
                query: DnsQuery {
                    hostname: "example.com".into(),
                    type_id: 1,
                    class: 1,
                },
                response: None,
                src: Endpoint {
                    ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                    port: Some(52341),
                    hostname: None,
                },
                dst: Endpoint {
                    ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                    port: Some(53),
                    hostname: None,
                },
            }),
        );

        assert!(!evt.id.is_nil());
        assert!(evt.ingest_time > 0);
        assert_eq!(evt.class_uid, 4003);
    }

    #[test]
    fn event_serde_roundtrip() {
        let evt = NousEvent::new(
            1_000_000_000,
            1001,
            1,
            Severity::Low,
            EventSource {
                adapter: AdapterType::Journald,
                product: None,
                sensor: Some("gateway-01".into()),
                original_id: None,
            },
            EventPayload::SystemLog(SystemLog {
                source_name: "sshd".into(),
                message: "Failed password for root".into(),
            }),
        );

        let json = serde_json::to_string(&evt).unwrap();
        let deser: NousEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.class_uid, evt.class_uid);
        assert_eq!(deser.severity, evt.severity);
    }
}
