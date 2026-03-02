//! Suricata EVE JSON adapter.
//!
//! Converts Suricata EVE JSON events into normalized Nous Core events.
//! Handles alert, dns, flow event types; everything else becomes Generic.

use std::net::IpAddr;

use chrono::DateTime;
use serde_json::Value;

use nous_core::error::{NousError, Result};
use nous_core::event::{
    AdapterType, DetectionFinding, DetectionRule, DnsActivity, DnsAnswer, DnsQuery, DnsResponse,
    Endpoint, EventPayload, EventSource, FindingStatus, GenericEvent, NetworkConnection, NousEvent,
    RiskLevel,
};
use nous_core::severity::Severity;

use crate::Adapter;

/// Suricata EVE JSON adapter.
pub struct SuricataAdapter;

impl SuricataAdapter {
    /// Create a new Suricata adapter.
    pub fn new() -> Self {
        Self
    }
}

impl Default for SuricataAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for SuricataAdapter {
    fn name(&self) -> &'static str {
        "suricata"
    }

    fn parse_line(&self, line: &str) -> Result<Option<NousEvent>> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(None);
        }

        let v: Value = serde_json::from_str(line)?;
        parse_eve_value(&v)
    }
}

/// Parse a single Suricata EVE JSON line into a NousEvent.
///
/// # Errors
///
/// Returns `NousError::Normalization` if the JSON is malformed or
/// missing required fields.
pub fn parse_eve_line(line: &str) -> Result<Option<NousEvent>> {
    SuricataAdapter::new().parse_line(line)
}

/// Map Suricata alert priority to Severity.
///
/// Priority 1 → High, 2 → Medium, 3 → Low, 4+ → Info.
fn priority_to_severity(priority: u64) -> Severity {
    match priority {
        1 => Severity::High,
        2 => Severity::Medium,
        3 => Severity::Low,
        _ => Severity::Info,
    }
}

/// Map Suricata alert priority to RiskLevel.
fn priority_to_risk_level(priority: u64) -> RiskLevel {
    match priority {
        1 => RiskLevel::High,
        2 => RiskLevel::Medium,
        3 => RiskLevel::Low,
        _ => RiskLevel::Info,
    }
}

/// Map Suricata alert priority to a risk score (0-100).
fn priority_to_risk_score(priority: u64) -> u8 {
    match priority {
        1 => 80,
        2 => 60,
        3 => 40,
        _ => 20,
    }
}

/// Parse a Suricata timestamp string into nanoseconds.
fn parse_timestamp(v: &Value) -> Result<i64> {
    let ts_str = v["timestamp"]
        .as_str()
        .ok_or_else(|| NousError::Normalization("missing timestamp field".into()))?;

    DateTime::parse_from_rfc3339(ts_str)
        .or_else(|_| {
            // Suricata uses a slightly non-standard format: "2024-01-15T10:30:00.000000+0000"
            DateTime::parse_from_str(ts_str, "%Y-%m-%dT%H:%M:%S%.f%z")
        })
        .map(|dt| dt.timestamp_nanos_opt().unwrap_or(0))
        .map_err(|e| NousError::Normalization(format!("invalid timestamp '{ts_str}': {e}")))
}

/// Parse an IP address from a JSON value, returning a default on failure.
fn parse_ip(v: &Value, field: &str) -> IpAddr {
    v[field]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

/// Parse a port number from a JSON value.
fn parse_port(v: &Value, field: &str) -> Option<u16> {
    v[field].as_u64().map(|p| p as u16)
}

/// Build an EventSource for Suricata events.
fn suricata_source() -> EventSource {
    EventSource {
        adapter: AdapterType::Suricata,
        product: Some("Suricata".into()),
        sensor: None,
        original_id: None,
    }
}

/// Parse a parsed JSON value into a NousEvent.
fn parse_eve_value(v: &Value) -> Result<Option<NousEvent>> {
    let event_type = v["event_type"]
        .as_str()
        .ok_or_else(|| NousError::Normalization("missing event_type field".into()))?;

    let time = parse_timestamp(v)?;

    match event_type {
        "alert" => parse_alert(v, time).map(Some),
        "dns" => parse_dns(v, time).map(Some),
        "flow" => parse_flow(v, time).map(Some),
        other => Ok(Some(NousEvent::new(
            time,
            0,
            0,
            Severity::Info,
            suricata_source(),
            EventPayload::Generic(GenericEvent {
                event_type: other.to_string(),
                data: v.clone(),
            }),
        ))),
    }
}

/// Parse a Suricata alert event into a DetectionFinding.
fn parse_alert(v: &Value, time: i64) -> Result<NousEvent> {
    let alert = &v["alert"];
    let signature = alert["signature"].as_str().unwrap_or("unknown").to_string();
    let sid = alert["signature_id"].as_u64().unwrap_or(0);
    let category = alert["category"].as_str().unwrap_or("").to_string();
    let priority = alert["severity"].as_u64().unwrap_or(4);

    let severity = priority_to_severity(priority);
    let risk_level = priority_to_risk_level(priority);
    let risk_score = priority_to_risk_score(priority);

    let rule = DetectionRule {
        uid: sid.to_string(),
        name: signature.clone(),
        source: category,
    };

    let finding = DetectionFinding {
        title: signature,
        description: alert["metadata"].as_object().map(|m| format!("{m:?}")),
        risk_score,
        risk_level,
        rule: Some(rule),
        entities: Vec::new(),
        status: FindingStatus::New,
    };

    Ok(NousEvent::new(
        time,
        2004,
        2,
        severity,
        suricata_source(),
        EventPayload::DetectionFinding(finding),
    ))
}

/// Parse a Suricata DNS event into a DnsActivity.
fn parse_dns(v: &Value, time: i64) -> Result<NousEvent> {
    let dns = &v["dns"];

    let rrname = dns["rrname"].as_str().unwrap_or("").to_string();
    let rrtype = dns["rrtype"].as_str().unwrap_or("A");
    let type_id = dns_type_to_id(rrtype);

    let answers = if let Some(arr) = dns["answers"].as_array() {
        arr.iter()
            .filter_map(|a| {
                let rdata = a["rdata"].as_str()?.to_string();
                let ttl = a["ttl"].as_u64().unwrap_or(0) as u32;
                let atype = a["rrtype"].as_str().unwrap_or("A");
                Some(DnsAnswer {
                    type_id: dns_type_to_id(atype),
                    rdata,
                    ttl,
                })
            })
            .collect()
    } else if let Some(rdata) = dns["rdata"].as_str() {
        vec![DnsAnswer {
            type_id,
            rdata: rdata.to_string(),
            ttl: dns["ttl"].as_u64().unwrap_or(0) as u32,
        }]
    } else {
        Vec::new()
    };

    // Determine if this is a query (1) or response (2)
    let dns_type = dns["type"].as_str().unwrap_or("query");
    let activity_id = if dns_type == "answer" { 2 } else { 1 };

    let response = if activity_id == 2 {
        let rcode_id = dns["rcode"].as_str().map(rcode_to_id).unwrap_or(0);
        Some(DnsResponse { rcode_id, answers })
    } else {
        None
    };

    let query = DnsQuery {
        hostname: rrname,
        type_id,
        class: 1, // IN class
    };

    let src = Endpoint {
        ip: parse_ip(v, "src_ip"),
        port: parse_port(v, "src_port"),
        hostname: None,
    };
    let dst = Endpoint {
        ip: parse_ip(v, "dest_ip"),
        port: parse_port(v, "dest_port"),
        hostname: None,
    };

    let dns_activity = DnsActivity {
        activity_id,
        query,
        response,
        src,
        dst,
    };

    Ok(NousEvent::new(
        time,
        4003,
        4,
        Severity::Info,
        suricata_source(),
        EventPayload::DnsActivity(dns_activity),
    ))
}

/// Parse a Suricata flow event into a NetworkConnection.
fn parse_flow(v: &Value, time: i64) -> Result<NousEvent> {
    let flow = &v["flow"];

    let protocol = v["proto"].as_str().unwrap_or("unknown").to_uppercase();
    let protocol_id = match protocol.as_str() {
        "TCP" => 6,
        "UDP" => 17,
        "ICMP" => 1,
        _ => 0,
    };

    let bytes_out = flow["bytes_toserver"].as_u64();
    let bytes_in = flow["bytes_toclient"].as_u64();

    // Duration: Suricata provides start/end timestamps or age
    let duration_us = flow["age"].as_u64().map(|s| s * 1_000_000);

    let src = Endpoint {
        ip: parse_ip(v, "src_ip"),
        port: parse_port(v, "src_port"),
        hostname: None,
    };
    let dst = Endpoint {
        ip: parse_ip(v, "dest_ip"),
        port: parse_port(v, "dest_port"),
        hostname: None,
    };

    let conn = NetworkConnection {
        src,
        dst,
        protocol_id,
        bytes_out,
        bytes_in,
        duration_us,
    };

    Ok(NousEvent::new(
        time,
        4001,
        4,
        Severity::Info,
        suricata_source(),
        EventPayload::NetworkConnection(conn),
    ))
}

/// Convert DNS record type string to numeric ID.
fn dns_type_to_id(rrtype: &str) -> u16 {
    match rrtype {
        "A" => 1,
        "AAAA" => 28,
        "CNAME" => 5,
        "MX" => 15,
        "NS" => 2,
        "PTR" => 12,
        "SOA" => 6,
        "SRV" => 33,
        "TXT" => 16,
        _ => 0,
    }
}

/// Convert DNS response code string to numeric ID.
fn rcode_to_id(rcode: &str) -> u8 {
    match rcode {
        "NOERROR" => 0,
        "FORMERR" => 1,
        "SERVFAIL" => 2,
        "NXDOMAIN" => 3,
        "NOTIMP" => 4,
        "REFUSED" => 5,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_alert_json() -> String {
        serde_json::json!({
            "timestamp": "2024-01-15T10:30:00.000000+0000",
            "event_type": "alert",
            "src_ip": "10.0.0.1",
            "src_port": 54321,
            "dest_ip": "192.168.1.1",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2024001,
                "rev": 1,
                "signature": "ET MALWARE Known Bad C2 Channel",
                "category": "A Network Trojan was detected",
                "severity": 1
            }
        })
        .to_string()
    }

    fn make_dns_query_json() -> String {
        serde_json::json!({
            "timestamp": "2024-01-15T10:30:01.000000+0000",
            "event_type": "dns",
            "src_ip": "10.0.0.5",
            "src_port": 44123,
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "proto": "UDP",
            "dns": {
                "type": "query",
                "rrname": "example.com",
                "rrtype": "A",
                "id": 12345
            }
        })
        .to_string()
    }

    fn make_dns_answer_json() -> String {
        serde_json::json!({
            "timestamp": "2024-01-15T10:30:01.100000+0000",
            "event_type": "dns",
            "src_ip": "8.8.8.8",
            "src_port": 53,
            "dest_ip": "10.0.0.5",
            "dest_port": 44123,
            "proto": "UDP",
            "dns": {
                "type": "answer",
                "rrname": "example.com",
                "rrtype": "A",
                "rcode": "NOERROR",
                "answers": [
                    { "rrtype": "A", "rdata": "93.184.216.34", "ttl": 300 }
                ]
            }
        })
        .to_string()
    }

    fn make_flow_json() -> String {
        serde_json::json!({
            "timestamp": "2024-01-15T10:31:00.000000+0000",
            "event_type": "flow",
            "src_ip": "10.0.0.1",
            "src_port": 54321,
            "dest_ip": "93.184.216.34",
            "dest_port": 443,
            "proto": "TCP",
            "flow": {
                "pkts_toserver": 10,
                "pkts_toclient": 8,
                "bytes_toserver": 1500,
                "bytes_toclient": 32000,
                "start": "2024-01-15T10:30:00.000000+0000",
                "age": 60,
                "state": "closed",
                "reason": "timeout"
            }
        })
        .to_string()
    }

    #[test]
    fn parse_alert_event() {
        let adapter = SuricataAdapter::new();
        let evt = adapter.parse_line(&make_alert_json()).unwrap().unwrap();
        assert_eq!(evt.class_uid, 2004);
        assert_eq!(evt.severity, Severity::High);
        match &evt.payload {
            EventPayload::DetectionFinding(f) => {
                assert_eq!(f.title, "ET MALWARE Known Bad C2 Channel");
                assert_eq!(f.risk_level, RiskLevel::High);
                assert_eq!(f.risk_score, 80);
                let rule = f.rule.as_ref().unwrap();
                assert_eq!(rule.uid, "2024001");
            }
            _ => panic!("expected DetectionFinding"),
        }
    }

    #[test]
    fn parse_dns_query_event() {
        let adapter = SuricataAdapter::new();
        let evt = adapter.parse_line(&make_dns_query_json()).unwrap().unwrap();
        assert_eq!(evt.class_uid, 4003);
        assert_eq!(evt.severity, Severity::Info);
        match &evt.payload {
            EventPayload::DnsActivity(d) => {
                assert_eq!(d.activity_id, 1);
                assert_eq!(d.query.hostname, "example.com");
                assert_eq!(d.query.type_id, 1); // A record
                assert!(d.response.is_none());
            }
            _ => panic!("expected DnsActivity"),
        }
    }

    #[test]
    fn parse_dns_answer_event() {
        let adapter = SuricataAdapter::new();
        let evt = adapter
            .parse_line(&make_dns_answer_json())
            .unwrap()
            .unwrap();
        match &evt.payload {
            EventPayload::DnsActivity(d) => {
                assert_eq!(d.activity_id, 2);
                let resp = d.response.as_ref().unwrap();
                assert_eq!(resp.rcode_id, 0);
                assert_eq!(resp.answers.len(), 1);
                assert_eq!(resp.answers[0].rdata, "93.184.216.34");
                assert_eq!(resp.answers[0].ttl, 300);
            }
            _ => panic!("expected DnsActivity"),
        }
    }

    #[test]
    fn parse_flow_event() {
        let adapter = SuricataAdapter::new();
        let evt = adapter.parse_line(&make_flow_json()).unwrap().unwrap();
        assert_eq!(evt.class_uid, 4001);
        match &evt.payload {
            EventPayload::NetworkConnection(c) => {
                assert_eq!(c.protocol_id, 6); // TCP
                assert_eq!(c.bytes_out, Some(1500));
                assert_eq!(c.bytes_in, Some(32000));
                assert_eq!(c.duration_us, Some(60_000_000));
                assert_eq!(c.dst.port, Some(443));
            }
            _ => panic!("expected NetworkConnection"),
        }
    }

    #[test]
    fn unknown_event_type_becomes_generic() {
        let json = serde_json::json!({
            "timestamp": "2024-01-15T10:30:00.000000+0000",
            "event_type": "fileinfo",
            "src_ip": "10.0.0.1",
            "fileinfo": {
                "filename": "/index.html",
                "size": 2048
            }
        })
        .to_string();

        let adapter = SuricataAdapter::new();
        let evt = adapter.parse_line(&json).unwrap().unwrap();
        assert_eq!(evt.class_uid, 0);
        match &evt.payload {
            EventPayload::Generic(g) => {
                assert_eq!(g.event_type, "fileinfo");
                assert_eq!(g.data["fileinfo"]["size"], 2048);
            }
            _ => panic!("expected Generic"),
        }
    }

    #[test]
    fn malformed_json_returns_error() {
        let adapter = SuricataAdapter::new();
        let result = adapter.parse_line("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn missing_event_type_returns_error() {
        let json = serde_json::json!({
            "timestamp": "2024-01-15T10:30:00.000000+0000",
            "src_ip": "10.0.0.1"
        })
        .to_string();

        let adapter = SuricataAdapter::new();
        let result = adapter.parse_line(&json);
        assert!(result.is_err());
    }

    #[test]
    fn empty_line_returns_none() {
        let adapter = SuricataAdapter::new();
        assert!(adapter.parse_line("").unwrap().is_none());
        assert!(adapter.parse_line("   ").unwrap().is_none());
    }

    #[test]
    fn severity_mapping() {
        assert_eq!(priority_to_severity(1), Severity::High);
        assert_eq!(priority_to_severity(2), Severity::Medium);
        assert_eq!(priority_to_severity(3), Severity::Low);
        assert_eq!(priority_to_severity(4), Severity::Info);
        assert_eq!(priority_to_severity(100), Severity::Info);
    }

    #[test]
    fn timestamp_parsing_rfc3339() {
        let v = serde_json::json!({
            "timestamp": "2024-01-15T10:30:00.000000+00:00"
        });
        let ts = parse_timestamp(&v).unwrap();
        assert!(ts > 0);
    }

    #[test]
    fn timestamp_parsing_suricata_format() {
        let v = serde_json::json!({
            "timestamp": "2024-01-15T10:30:00.000000+0000"
        });
        let ts = parse_timestamp(&v).unwrap();
        assert!(ts > 0);
    }

    #[test]
    fn alert_serde_roundtrip() {
        let adapter = SuricataAdapter::new();
        let evt = adapter.parse_line(&make_alert_json()).unwrap().unwrap();
        let json = serde_json::to_string(&evt).unwrap();
        let deser: NousEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.class_uid, evt.class_uid);
        assert_eq!(deser.severity, evt.severity);
    }
}
