use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::action::AgentAction;
use crate::entity::Entity;
use crate::severity::Severity;
use crate::verdict::Verdict;

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

    /// Raw source line preserved for audit trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
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
            raw: None,
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
    HttpActivity(HttpActivity),
    TlsActivity(TlsActivity),
    ProcessActivity(ProcessActivity),
    Authentication(Authentication),
    SystemLog(SystemLog),
    CorrelationFinding(CorrelationFinding),
    AgentAction(AgentAction),
    Verdict(Verdict),
    StateSnapshot(StateSnapshot),
    Generic(GenericEvent),
}

/// OCSF class_uid: 2001 (Correlation Finding).
///
/// Produced by the correlation engine when multiple events match a rule
/// within a sliding time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationFinding {
    /// Human-readable title for the correlation finding.
    pub title: String,
    /// Detailed description of the correlated activity.
    pub description: String,
    /// Which correlation rule fired.
    pub rule_id: CorrelationRuleId,
    /// Entities involved in the correlation.
    pub entities: Vec<Entity>,
    /// IDs of the source events that contributed to this finding.
    pub source_event_ids: Vec<Uuid>,
    /// Number of signals that matched the rule.
    pub signal_count: u32,
    /// Start of the correlation window (epoch nanos).
    pub window_start: i64,
    /// End of the correlation window (epoch nanos).
    pub window_end: i64,
    /// Computed risk score (0-100).
    pub risk_score: u8,
    /// Risk level classification.
    pub risk_level: RiskLevel,
    /// Finding status.
    pub status: FindingStatus,
    /// Optional MITRE ATT&CK mapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attack: Option<AttackMapping>,
}

/// Correlation rule identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationRuleId {
    /// Multiple DetectionFindings share entities within a window.
    EntityCluster,
    /// Excessive DNS queries from a single source IP.
    HighFrequencyDns,
    /// User-defined correlation rule.
    Custom(String),
}

/// Fallback for unrecognized event types — preserves the raw data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericEvent {
    /// Source event type string (e.g., "fileinfo", "tls").
    pub event_type: String,
    /// Raw event data preserved as-is.
    pub data: serde_json::Value,
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

/// DNS query information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub hostname: String,
    pub type_id: u16,
    pub class: u16,
    /// DNS transaction ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_uid: Option<u16>,
}

/// DNS response information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResponse {
    pub rcode_id: u8,
    pub answers: Vec<DnsAnswer>,
}

/// A single DNS answer record.
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
    /// MITRE ATT&CK mapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attack: Option<AttackMapping>,
}

/// MITRE ATT&CK technique mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackMapping {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
}

/// Detection rule metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub uid: String,
    pub name: String,
    pub source: String,
}

/// Finding status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    New,
    InProgress,
    Resolved,
    Suppressed,
}

/// Risk level classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// OCSF class_uid: 4002 (HTTP Activity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpActivity {
    pub url: String,
    pub method: String,
    pub status_code: Option<u16>,
    pub request_headers: Vec<HttpHeader>,
    pub response_headers: Vec<HttpHeader>,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub bytes: Option<u64>,
}

/// HTTP header key-value pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

/// OCSF class_uid: 4014 (TLS Activity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsActivity {
    pub server_name: Option<String>,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub certificate_chain: Vec<TlsCertificate>,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub src: Endpoint,
    pub dst: Endpoint,
}

/// TLS certificate information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCertificate {
    pub subject: String,
    pub issuer: String,
    pub serial: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

/// OCSF class_uid: 1001 (Process Activity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessActivity {
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub name: String,
    pub cmd_line: Option<String>,
    pub user: Option<String>,
    pub file_path: Option<String>,
    pub action: ProcessAction,
}

/// Process lifecycle action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessAction {
    Start,
    Stop,
    Modify,
}

/// OCSF class_uid: 3001 (Authentication).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authentication {
    pub user: String,
    pub src: Option<Endpoint>,
    pub auth_protocol: AuthProtocol,
    pub activity: AuthActivity,
    pub status: AuthStatus,
}

/// Authentication protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthProtocol {
    Ssh,
    Kerberos,
    Ldap,
    Local,
    Unknown,
}

/// Authentication activity type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthActivity {
    Login,
    Logout,
    FailedLogin,
}

/// Authentication outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthStatus {
    Success,
    Failure,
}

/// State snapshot event for periodic state emission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub snapshot_time: i64,
    pub event_count: u64,
    pub active_findings: u64,
    pub class_counts: Vec<(u32, u64)>,
    pub entity_scores: Vec<EntityScore>,
}

/// Entity score entry in a state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityScore {
    pub entity_type: String,
    pub value: String,
    pub score: u8,
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
    /// MAC address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
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
                    transaction_uid: None,
                },
                response: None,
                src: Endpoint {
                    ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                    port: Some(52341),
                    hostname: None,
                    mac: None,
                },
                dst: Endpoint {
                    ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                    port: Some(53),
                    hostname: None,
                    mac: None,
                },
            }),
        );

        assert!(!evt.id.is_nil());
        assert!(evt.ingest_time > 0);
        assert_eq!(evt.class_uid, 4003);
        assert!(evt.raw.is_none());
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

    #[test]
    fn generic_event_serde_roundtrip() {
        let evt = NousEvent::new(
            1_000_000_000,
            0,
            0,
            Severity::Info,
            EventSource {
                adapter: AdapterType::Suricata,
                product: None,
                sensor: None,
                original_id: None,
            },
            EventPayload::Generic(GenericEvent {
                event_type: "fileinfo".into(),
                data: serde_json::json!({
                    "filename": "/index.html",
                    "size": 1024
                }),
            }),
        );

        let json = serde_json::to_string(&evt).unwrap();
        let deser: NousEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.class_uid, 0);
        match &deser.payload {
            EventPayload::Generic(g) => {
                assert_eq!(g.event_type, "fileinfo");
                assert_eq!(g.data["size"], 1024);
            }
            _ => panic!("expected Generic payload"),
        }
    }

    #[test]
    fn http_activity_serde_roundtrip() {
        let http = HttpActivity {
            url: "https://example.com/api".into(),
            method: "GET".into(),
            status_code: Some(200),
            request_headers: vec![HttpHeader {
                name: "Host".into(),
                value: "example.com".into(),
            }],
            response_headers: vec![],
            src: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: Some(54321),
                hostname: None,
                mac: None,
            },
            dst: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                port: Some(443),
                hostname: None,
                mac: None,
            },
            user_agent: Some("curl/8.0".into()),
            content_type: Some("application/json".into()),
            bytes: Some(1024),
        };
        let evt = NousEvent::new(
            1_000_000_000,
            4002,
            4,
            Severity::Info,
            EventSource {
                adapter: AdapterType::Suricata,
                product: None,
                sensor: None,
                original_id: None,
            },
            EventPayload::HttpActivity(http),
        );
        let json = serde_json::to_string(&evt).unwrap();
        let deser: NousEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.class_uid, 4002);
        match &deser.payload {
            EventPayload::HttpActivity(h) => {
                assert_eq!(h.method, "GET");
                assert_eq!(h.status_code, Some(200));
            }
            _ => panic!("expected HttpActivity"),
        }
    }

    #[test]
    fn tls_activity_serde_roundtrip() {
        let tls = TlsActivity {
            server_name: Some("example.com".into()),
            ja3: Some("abc123".into()),
            ja3s: Some("def456".into()),
            certificate_chain: vec![TlsCertificate {
                subject: "CN=example.com".into(),
                issuer: "CN=Let's Encrypt".into(),
                serial: Some("DEADBEEF".into()),
                not_before: Some("2024-01-01".into()),
                not_after: Some("2025-01-01".into()),
            }],
            tls_version: Some("TLSv1.3".into()),
            cipher_suite: Some("TLS_AES_256_GCM_SHA384".into()),
            src: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: Some(54321),
                hostname: None,
                mac: None,
            },
            dst: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                port: Some(443),
                hostname: None,
                mac: None,
            },
        };
        let evt = NousEvent::new(
            1_000_000_000,
            4014,
            4,
            Severity::Info,
            EventSource {
                adapter: AdapterType::Suricata,
                product: None,
                sensor: None,
                original_id: None,
            },
            EventPayload::TlsActivity(tls),
        );
        let json = serde_json::to_string(&evt).unwrap();
        let deser: NousEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.class_uid, 4014);
    }

    #[test]
    fn process_activity_serde_roundtrip() {
        let proc_evt = ProcessActivity {
            pid: Some(1234),
            ppid: Some(1),
            name: "malware.exe".into(),
            cmd_line: Some("/tmp/malware.exe --flag".into()),
            user: Some("root".into()),
            file_path: Some("/tmp/malware.exe".into()),
            action: ProcessAction::Start,
        };
        let evt = NousEvent::new(
            1_000_000_000,
            1001,
            1,
            Severity::High,
            EventSource {
                adapter: AdapterType::Journald,
                product: None,
                sensor: None,
                original_id: None,
            },
            EventPayload::ProcessActivity(proc_evt),
        );
        let json = serde_json::to_string(&evt).unwrap();
        let deser: NousEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.class_uid, 1001);
        match &deser.payload {
            EventPayload::ProcessActivity(p) => {
                assert_eq!(p.pid, Some(1234));
                assert_eq!(p.action, ProcessAction::Start);
            }
            _ => panic!("expected ProcessActivity"),
        }
    }

    #[test]
    fn authentication_serde_roundtrip() {
        let auth = Authentication {
            user: "admin".into(),
            src: Some(Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
                port: None,
                hostname: None,
                mac: None,
            }),
            auth_protocol: AuthProtocol::Ssh,
            activity: AuthActivity::FailedLogin,
            status: AuthStatus::Failure,
        };
        let evt = NousEvent::new(
            1_000_000_000,
            3001,
            3,
            Severity::Medium,
            EventSource {
                adapter: AdapterType::Syslog,
                product: None,
                sensor: None,
                original_id: None,
            },
            EventPayload::Authentication(auth),
        );
        let json = serde_json::to_string(&evt).unwrap();
        let deser: NousEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.class_uid, 3001);
        match &deser.payload {
            EventPayload::Authentication(a) => {
                assert_eq!(a.user, "admin");
                assert_eq!(a.auth_protocol, AuthProtocol::Ssh);
                assert_eq!(a.activity, AuthActivity::FailedLogin);
                assert_eq!(a.status, AuthStatus::Failure);
            }
            _ => panic!("expected Authentication"),
        }
    }

    #[test]
    fn state_snapshot_serde_roundtrip() {
        let snap = StateSnapshot {
            snapshot_time: 1_000_000_000,
            event_count: 500,
            active_findings: 3,
            class_counts: vec![(4003, 200), (2004, 10)],
            entity_scores: vec![EntityScore {
                entity_type: "ip_address".into(),
                value: "10.0.0.1".into(),
                score: 75,
            }],
        };
        let evt = NousEvent::new(
            1_000_000_000,
            0,
            0,
            Severity::Info,
            EventSource {
                adapter: AdapterType::NousInternal,
                product: None,
                sensor: None,
                original_id: None,
            },
            EventPayload::StateSnapshot(snap),
        );
        let json = serde_json::to_string(&evt).unwrap();
        let deser: NousEvent = serde_json::from_str(&json).unwrap();
        match &deser.payload {
            EventPayload::StateSnapshot(s) => {
                assert_eq!(s.event_count, 500);
                assert_eq!(s.entity_scores.len(), 1);
            }
            _ => panic!("expected StateSnapshot"),
        }
    }

    #[test]
    fn correlation_finding_serde_roundtrip() {
        use crate::entity::Entity;

        let finding = CorrelationFinding {
            title: "Entity cluster detected".into(),
            description: "3 findings share entity 10.0.0.1".into(),
            rule_id: CorrelationRuleId::EntityCluster,
            entities: vec![Entity::new(
                crate::entity::EntityType::IpAddress,
                "10.0.0.1",
            )],
            source_event_ids: vec![Uuid::nil()],
            signal_count: 3,
            window_start: 1_000_000_000,
            window_end: 2_000_000_000,
            risk_score: 80,
            risk_level: RiskLevel::High,
            status: FindingStatus::New,
            attack: None,
        };
        let evt = NousEvent::new(
            1_000_000_000,
            2001,
            2,
            Severity::High,
            EventSource {
                adapter: AdapterType::NousInternal,
                product: None,
                sensor: None,
                original_id: None,
            },
            EventPayload::CorrelationFinding(finding),
        );
        let json = serde_json::to_string(&evt).unwrap();
        let deser: NousEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.class_uid, 2001);
        match &deser.payload {
            EventPayload::CorrelationFinding(cf) => {
                assert_eq!(cf.title, "Entity cluster detected");
                assert_eq!(cf.rule_id, CorrelationRuleId::EntityCluster);
                assert_eq!(cf.signal_count, 3);
                assert_eq!(cf.risk_score, 80);
            }
            _ => panic!("expected CorrelationFinding payload"),
        }
    }

    #[test]
    fn correlation_rule_id_variants_serde() {
        let variants = vec![
            CorrelationRuleId::EntityCluster,
            CorrelationRuleId::HighFrequencyDns,
            CorrelationRuleId::Custom("my_rule".into()),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let deser: CorrelationRuleId = serde_json::from_str(&json).unwrap();
            assert_eq!(&deser, v);
        }
    }

    #[test]
    fn process_action_all_variants() {
        let variants = [
            ProcessAction::Start,
            ProcessAction::Stop,
            ProcessAction::Modify,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let deser: ProcessAction = serde_json::from_str(&json).unwrap();
            assert_eq!(&deser, v);
        }
    }

    #[test]
    fn auth_enums_all_variants() {
        // AuthProtocol
        for v in &[
            AuthProtocol::Ssh,
            AuthProtocol::Kerberos,
            AuthProtocol::Ldap,
            AuthProtocol::Local,
            AuthProtocol::Unknown,
        ] {
            let json = serde_json::to_string(v).unwrap();
            let deser: AuthProtocol = serde_json::from_str(&json).unwrap();
            assert_eq!(&deser, v);
        }
        // AuthActivity
        for v in &[
            AuthActivity::Login,
            AuthActivity::Logout,
            AuthActivity::FailedLogin,
        ] {
            let json = serde_json::to_string(v).unwrap();
            let deser: AuthActivity = serde_json::from_str(&json).unwrap();
            assert_eq!(&deser, v);
        }
        // AuthStatus
        for v in &[AuthStatus::Success, AuthStatus::Failure] {
            let json = serde_json::to_string(v).unwrap();
            let deser: AuthStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&deser, v);
        }
    }

    #[test]
    fn raw_field_backward_compat() {
        // Events serialized without raw should still deserialize
        let evt = NousEvent::new(
            1_000_000_000,
            0,
            0,
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
        );
        let json = serde_json::to_string(&evt).unwrap();
        // raw should not appear in JSON when None
        assert!(!json.contains("\"raw\""));
        let deser: NousEvent = serde_json::from_str(&json).unwrap();
        assert!(deser.raw.is_none());
    }

    #[test]
    fn endpoint_mac_backward_compat() {
        let ep = Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: Some(80),
            hostname: None,
            mac: None,
        };
        let json = serde_json::to_string(&ep).unwrap();
        assert!(!json.contains("\"mac\""));
        let deser: Endpoint = serde_json::from_str(&json).unwrap();
        assert!(deser.mac.is_none());
    }

    #[test]
    fn attack_mapping_serde_roundtrip() {
        let mapping = AttackMapping {
            technique_id: "T1071.001".into(),
            technique_name: "Application Layer Protocol: Web Protocols".into(),
            tactic: "command-and-control".into(),
        };
        let json = serde_json::to_string(&mapping).unwrap();
        let deser: AttackMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.technique_id, "T1071.001");
    }
}
