//! Zeek tab-separated log adapter.
//!
//! Parses Zeek log lines (conn.log, dns.log, http.log, ssl.log, notice.log)
//! into normalized Nous Core events. Header directives (#path, #fields)
//! are tracked via internal state.

use std::sync::Mutex;

use nous_core::error::{NousError, Result};
use nous_core::event::{
    AdapterType, DetectionFinding, DnsActivity, DnsQuery, Endpoint, EventPayload, EventSource,
    FindingStatus, GenericEvent, HttpActivity, NetworkConnection, NousEvent, RiskLevel,
    TlsActivity, TlsCertificate,
};
use nous_core::severity::Severity;

use crate::Adapter;

/// Internal parser state tracking header directives.
#[derive(Debug, Default)]
struct ZeekParserState {
    /// Current log type from #path directive.
    log_type: Option<String>,
    /// Column names from #fields directive.
    fields: Vec<String>,
}

/// Zeek tab-separated log adapter.
pub struct ZeekAdapter {
    state: Mutex<ZeekParserState>,
}

impl ZeekAdapter {
    /// Create a new Zeek adapter.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ZeekParserState::default()),
        }
    }
}

impl Default for ZeekAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for ZeekAdapter {
    fn name(&self) -> &'static str {
        "zeek"
    }

    fn parse_line(&self, line: &str) -> Result<Option<NousEvent>> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(None);
        }

        // Handle header/comment lines
        if line.starts_with('#') {
            let mut state = self
                .state
                .lock()
                .map_err(|e| NousError::State(format!("lock poisoned: {e}")))?;

            if let Some(rest) = line.strip_prefix("#path\t") {
                state.log_type = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("#fields\t") {
                state.fields = rest.split('\t').map(|s| s.to_string()).collect();
            }
            return Ok(None);
        }

        let state = self
            .state
            .lock()
            .map_err(|e| NousError::State(format!("lock poisoned: {e}")))?;

        let cols: Vec<&str> = line.split('\t').collect();
        let log_type = state.log_type.as_deref().unwrap_or("unknown");

        if state.fields.is_empty() {
            return Err(NousError::Normalization(
                "no #fields header parsed yet".into(),
            ));
        }

        if cols.len() < state.fields.len() {
            return Err(NousError::Normalization(format!(
                "expected {} fields, got {}",
                state.fields.len(),
                cols.len()
            )));
        }

        // Build column lookup
        let get = |name: &str| -> &str {
            state
                .fields
                .iter()
                .position(|f| f == name)
                .and_then(|i| cols.get(i).copied())
                .unwrap_or("-")
        };

        let time = parse_zeek_ts(get("ts"))?;
        let source = zeek_source();

        match log_type {
            "conn" => parse_conn(&cols, &state.fields, time, source),
            "dns" => parse_dns_log(&cols, &state.fields, time, source),
            "http" => parse_http_log(&cols, &state.fields, time, source),
            "ssl" => parse_ssl_log(&cols, &state.fields, time, source),
            "notice" => parse_notice(&cols, &state.fields, time, source),
            other => Ok(Some(NousEvent::new(
                time,
                0,
                0,
                Severity::Info,
                source,
                EventPayload::Generic(GenericEvent {
                    event_type: format!("zeek_{other}"),
                    data: serde_json::json!({"raw_fields": cols}),
                }),
            ))),
        }
    }
}

/// Parse Zeek timestamp (epoch seconds with microsecond decimal).
fn parse_zeek_ts(s: &str) -> Result<i64> {
    if s == "-" {
        return Ok(0);
    }
    let f: f64 = s
        .parse()
        .map_err(|_| NousError::Normalization(format!("invalid zeek timestamp: {s}")))?;
    Ok((f * 1_000_000_000.0) as i64)
}

/// Helper to get a field value, treating "-" as unset.
fn field<'a>(cols: &'a [&str], fields: &[String], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .position(|f| f == name)
        .and_then(|i| cols.get(i).copied())
        .filter(|&v| v != "-")
}

/// Parse IP, returning unspecified for unset.
fn parse_zeek_ip(s: Option<&str>) -> std::net::IpAddr {
    s.and_then(|v| v.parse().ok())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

fn parse_zeek_port(s: Option<&str>) -> Option<u16> {
    s.and_then(|v| v.parse().ok())
}

fn zeek_source() -> EventSource {
    EventSource {
        adapter: AdapterType::Zeek,
        product: Some("Zeek".into()),
        sensor: None,
        original_id: None,
    }
}

fn make_endpoint(cols: &[&str], fields: &[String], ip_name: &str, port_name: &str) -> Endpoint {
    Endpoint {
        ip: parse_zeek_ip(field(cols, fields, ip_name)),
        port: parse_zeek_port(field(cols, fields, port_name)),
        hostname: None,
        mac: None,
    }
}

/// Parse conn.log -> NetworkConnection (4001)
fn parse_conn(
    cols: &[&str],
    fields: &[String],
    time: i64,
    source: EventSource,
) -> Result<Option<NousEvent>> {
    let proto_str = field(cols, fields, "proto").unwrap_or("tcp");
    let protocol_id = match proto_str.to_lowercase().as_str() {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        _ => 0,
    };

    let src = make_endpoint(cols, fields, "id.orig_h", "id.orig_p");
    let dst = make_endpoint(cols, fields, "id.resp_h", "id.resp_p");
    let bytes_out = field(cols, fields, "orig_bytes").and_then(|v| v.parse().ok());
    let bytes_in = field(cols, fields, "resp_bytes").and_then(|v| v.parse().ok());
    let duration_us = field(cols, fields, "duration")
        .and_then(|v| v.parse::<f64>().ok())
        .map(|d| (d * 1_000_000.0) as u64);

    Ok(Some(NousEvent::new(
        time,
        4001,
        4,
        Severity::Info,
        source,
        EventPayload::NetworkConnection(NetworkConnection {
            src,
            dst,
            protocol_id,
            bytes_out,
            bytes_in,
            duration_us,
        }),
    )))
}

/// Parse dns.log -> DnsActivity (4003)
fn parse_dns_log(
    cols: &[&str],
    fields: &[String],
    time: i64,
    source: EventSource,
) -> Result<Option<NousEvent>> {
    let src = make_endpoint(cols, fields, "id.orig_h", "id.orig_p");
    let dst = make_endpoint(cols, fields, "id.resp_h", "id.resp_p");
    let hostname = field(cols, fields, "query").unwrap_or("").to_string();
    let qtype = field(cols, fields, "qtype_name").unwrap_or("A");
    let type_id = dns_type_to_id(qtype);

    Ok(Some(NousEvent::new(
        time,
        4003,
        4,
        Severity::Info,
        source,
        EventPayload::DnsActivity(DnsActivity {
            activity_id: 1,
            query: DnsQuery {
                hostname,
                type_id,
                class: 1,
                transaction_uid: field(cols, fields, "trans_id").and_then(|v| v.parse().ok()),
            },
            response: None,
            src,
            dst,
        }),
    )))
}

/// Parse http.log -> HttpActivity (4002)
fn parse_http_log(
    cols: &[&str],
    fields: &[String],
    time: i64,
    source: EventSource,
) -> Result<Option<NousEvent>> {
    let src = make_endpoint(cols, fields, "id.orig_h", "id.orig_p");
    let dst = make_endpoint(cols, fields, "id.resp_h", "id.resp_p");
    let host = field(cols, fields, "host").unwrap_or("");
    let uri = field(cols, fields, "uri").unwrap_or("/");
    let url = if host.is_empty() {
        uri.to_string()
    } else {
        format!("{host}{uri}")
    };

    Ok(Some(NousEvent::new(
        time,
        4002,
        4,
        Severity::Info,
        source,
        EventPayload::HttpActivity(HttpActivity {
            url,
            method: field(cols, fields, "method").unwrap_or("GET").to_string(),
            status_code: field(cols, fields, "status_code").and_then(|v| v.parse().ok()),
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            src,
            dst,
            user_agent: field(cols, fields, "user_agent").map(String::from),
            content_type: field(cols, fields, "resp_mime_types").map(String::from),
            bytes: field(cols, fields, "resp_body_len").and_then(|v| v.parse().ok()),
        }),
    )))
}

/// Parse ssl.log -> TlsActivity (4014)
fn parse_ssl_log(
    cols: &[&str],
    fields: &[String],
    time: i64,
    source: EventSource,
) -> Result<Option<NousEvent>> {
    let src = make_endpoint(cols, fields, "id.orig_h", "id.orig_p");
    let dst = make_endpoint(cols, fields, "id.resp_h", "id.resp_p");

    let mut certificate_chain = Vec::new();
    let subject = field(cols, fields, "subject");
    let issuer = field(cols, fields, "issuer");
    if subject.is_some() || issuer.is_some() {
        certificate_chain.push(TlsCertificate {
            subject: subject.unwrap_or("").to_string(),
            issuer: issuer.unwrap_or("").to_string(),
            serial: None,
            not_before: field(cols, fields, "not_valid_before").map(String::from),
            not_after: field(cols, fields, "not_valid_after").map(String::from),
        });
    }

    Ok(Some(NousEvent::new(
        time,
        4014,
        4,
        Severity::Info,
        source,
        EventPayload::TlsActivity(TlsActivity {
            server_name: field(cols, fields, "server_name").map(String::from),
            ja3: field(cols, fields, "ja3").map(String::from),
            ja3s: field(cols, fields, "ja3s").map(String::from),
            certificate_chain,
            tls_version: field(cols, fields, "version").map(String::from),
            cipher_suite: field(cols, fields, "cipher").map(String::from),
            src,
            dst,
        }),
    )))
}

/// Parse notice.log -> DetectionFinding (2004)
fn parse_notice(
    cols: &[&str],
    fields: &[String],
    time: i64,
    source: EventSource,
) -> Result<Option<NousEvent>> {
    let note = field(cols, fields, "note").unwrap_or("Unknown").to_string();
    let msg = field(cols, fields, "msg").map(String::from);

    Ok(Some(NousEvent::new(
        time,
        2004,
        2,
        Severity::Medium,
        source,
        EventPayload::DetectionFinding(DetectionFinding {
            title: note,
            description: msg,
            risk_score: 50,
            risk_level: RiskLevel::Medium,
            rule: None,
            entities: Vec::new(),
            status: FindingStatus::New,
            attack: None,
        }),
    )))
}

fn dns_type_to_id(qtype: &str) -> u16 {
    match qtype {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_adapter(log_type: &str, fields: &str) -> ZeekAdapter {
        let adapter = ZeekAdapter::new();
        adapter.parse_line(&format!("#path\t{log_type}")).unwrap();
        adapter.parse_line(&format!("#fields\t{fields}")).unwrap();
        adapter
    }

    #[test]
    fn header_parsing() {
        let adapter = ZeekAdapter::new();
        // Comments should be skipped
        assert!(adapter.parse_line("#separator \\x09").unwrap().is_none());
        assert!(adapter.parse_line("#path\tconn").unwrap().is_none());
        assert!(adapter
            .parse_line("#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto")
            .unwrap()
            .is_none());
    }

    #[test]
    fn parse_conn_log() {
        let adapter = setup_adapter(
            "conn",
            "ts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\torig_bytes\tresp_bytes\tduration",
        );
        let evt = adapter
            .parse_line(
                "1705312201.123456\t10.0.0.1\t54321\t93.184.216.34\t443\ttcp\t1500\t32000\t1.5",
            )
            .unwrap()
            .unwrap();
        assert_eq!(evt.class_uid, 4001);
        match &evt.payload {
            EventPayload::NetworkConnection(c) => {
                assert_eq!(c.protocol_id, 6);
                assert_eq!(c.bytes_out, Some(1500));
                assert_eq!(c.bytes_in, Some(32000));
                assert_eq!(c.duration_us, Some(1_500_000));
            }
            _ => panic!("expected NetworkConnection"),
        }
    }

    #[test]
    fn parse_dns_log() {
        let adapter = setup_adapter(
            "dns",
            "ts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tquery\tqtype_name\ttrans_id",
        );
        let evt = adapter
            .parse_line("1705312201.123456\t10.0.0.5\t44123\t8.8.8.8\t53\texample.com\tA\t12345")
            .unwrap()
            .unwrap();
        assert_eq!(evt.class_uid, 4003);
        match &evt.payload {
            EventPayload::DnsActivity(d) => {
                assert_eq!(d.query.hostname, "example.com");
                assert_eq!(d.query.type_id, 1);
                assert_eq!(d.query.transaction_uid, Some(12345));
            }
            _ => panic!("expected DnsActivity"),
        }
    }

    #[test]
    fn parse_http_log() {
        let adapter = setup_adapter(
            "http",
            "ts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tmethod\thost\turi\tstatus_code\tuser_agent\tresp_mime_types\tresp_body_len",
        );
        let evt = adapter
            .parse_line("1705312201.123456\t10.0.0.1\t54321\t93.184.216.34\t80\tGET\texample.com\t/index.html\t200\tMozilla/5.0\ttext/html\t4096")
            .unwrap()
            .unwrap();
        assert_eq!(evt.class_uid, 4002);
        match &evt.payload {
            EventPayload::HttpActivity(h) => {
                assert_eq!(h.method, "GET");
                assert_eq!(h.url, "example.com/index.html");
                assert_eq!(h.status_code, Some(200));
            }
            _ => panic!("expected HttpActivity"),
        }
    }

    #[test]
    fn parse_ssl_log() {
        let adapter = setup_adapter(
            "ssl",
            "ts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tserver_name\tversion\tcipher\tsubject\tissuer\tja3\tja3s",
        );
        let evt = adapter
            .parse_line("1705312201.123456\t10.0.0.1\t54321\t93.184.216.34\t443\texample.com\tTLSv13\tAES256\tCN=example.com\tCN=CA\tabc\tdef")
            .unwrap()
            .unwrap();
        assert_eq!(evt.class_uid, 4014);
        match &evt.payload {
            EventPayload::TlsActivity(t) => {
                assert_eq!(t.server_name.as_deref(), Some("example.com"));
                assert_eq!(t.ja3.as_deref(), Some("abc"));
                assert_eq!(t.certificate_chain.len(), 1);
            }
            _ => panic!("expected TlsActivity"),
        }
    }

    #[test]
    fn parse_notice_log() {
        let adapter = setup_adapter("notice", "ts\tnote\tmsg\tsrc\tdst\tp\tn");
        let evt = adapter
            .parse_line("1705312201.123456\tScan::Port_Scan\tPort scan detected\t10.0.0.1\t-\t-\t-")
            .unwrap()
            .unwrap();
        assert_eq!(evt.class_uid, 2004);
        match &evt.payload {
            EventPayload::DetectionFinding(f) => {
                assert_eq!(f.title, "Scan::Port_Scan");
                assert_eq!(f.description.as_deref(), Some("Port scan detected"));
            }
            _ => panic!("expected DetectionFinding"),
        }
    }

    #[test]
    fn unknown_log_becomes_generic() {
        let adapter = setup_adapter("weird", "ts\tname\taddl");
        let evt = adapter
            .parse_line("1705312201.123456\tbad_hdr_clrf\t-")
            .unwrap()
            .unwrap();
        assert_eq!(evt.class_uid, 0);
        match &evt.payload {
            EventPayload::Generic(g) => {
                assert!(g.event_type.starts_with("zeek_"));
            }
            _ => panic!("expected Generic"),
        }
    }

    #[test]
    fn comment_lines_skipped() {
        let adapter = ZeekAdapter::new();
        assert!(adapter.parse_line("#separator \\x09").unwrap().is_none());
        assert!(adapter.parse_line("#open 2024-01-15").unwrap().is_none());
        assert!(adapter.parse_line("#close 2024-01-15").unwrap().is_none());
    }

    #[test]
    fn empty_line_skipped() {
        let adapter = ZeekAdapter::new();
        assert!(adapter.parse_line("").unwrap().is_none());
        assert!(adapter.parse_line("   ").unwrap().is_none());
    }

    #[test]
    fn missing_fields_header_returns_error() {
        let adapter = ZeekAdapter::new();
        adapter.parse_line("#path\tconn").unwrap();
        // No #fields header yet
        let result = adapter.parse_line("1705312201.123456\t10.0.0.1");
        assert!(result.is_err());
    }

    #[test]
    fn unset_field_handling() {
        let adapter = setup_adapter(
            "conn",
            "ts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\torig_bytes\tresp_bytes\tduration",
        );
        let evt = adapter
            .parse_line("1705312201.123456\t10.0.0.1\t54321\t10.0.0.2\t80\ttcp\t-\t-\t-")
            .unwrap()
            .unwrap();
        match &evt.payload {
            EventPayload::NetworkConnection(c) => {
                assert!(c.bytes_out.is_none());
                assert!(c.bytes_in.is_none());
                assert!(c.duration_us.is_none());
            }
            _ => panic!("expected NetworkConnection"),
        }
    }

    #[test]
    fn timestamp_parsing() {
        let ts = parse_zeek_ts("1705312201.123456").unwrap();
        assert!(ts > 0);
        assert_eq!(parse_zeek_ts("-").unwrap(), 0);
    }

    #[test]
    fn conn_serde_roundtrip() {
        let adapter = setup_adapter(
            "conn",
            "ts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\torig_bytes\tresp_bytes\tduration",
        );
        let evt = adapter
            .parse_line(
                "1705312201.123456\t10.0.0.1\t54321\t93.184.216.34\t443\ttcp\t100\t200\t1.0",
            )
            .unwrap()
            .unwrap();
        let json = serde_json::to_string(&evt).unwrap();
        let deser: NousEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.class_uid, 4001);
    }

    #[test]
    fn dns_serde_roundtrip() {
        let adapter = setup_adapter(
            "dns",
            "ts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tquery\tqtype_name\ttrans_id",
        );
        let evt = adapter
            .parse_line("1705312201.123456\t10.0.0.5\t44123\t8.8.8.8\t53\texample.com\tA\t12345")
            .unwrap()
            .unwrap();
        let json = serde_json::to_string(&evt).unwrap();
        let deser: NousEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.class_uid, 4003);
    }
}
