//! Journald JSON adapter.
//!
//! Parses JSON output from `journalctl -o json` into Nous Core events.
//! Process lifecycle entries map to ProcessActivity; sshd/sudo entries
//! map to Authentication; everything else becomes SystemLog.

use serde_json::Value;

use nous_core::error::{NousError, Result};
use nous_core::event::{
    AdapterType, AuthActivity, AuthProtocol, AuthStatus, Authentication, Endpoint, EventPayload,
    EventSource, NousEvent, ProcessAction, ProcessActivity, SystemLog,
};
use nous_core::severity::Severity;

use crate::Adapter;

/// Journald JSON adapter.
pub struct JournaldAdapter;

impl JournaldAdapter {
    /// Create a new journald adapter.
    pub fn new() -> Self {
        Self
    }
}

impl Default for JournaldAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for JournaldAdapter {
    fn name(&self) -> &'static str {
        "journald"
    }

    fn parse_line(&self, line: &str) -> Result<Option<NousEvent>> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(None);
        }

        let v: Value = serde_json::from_str(line)?;
        parse_journald_entry(&v)
    }
}

/// Parse a single journald JSON entry.
fn parse_journald_entry(v: &Value) -> Result<Option<NousEvent>> {
    let time = parse_realtime_timestamp(v)?;
    let priority = v["PRIORITY"]
        .as_str()
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(6);
    let severity = priority_to_severity(priority);
    let comm = v["_COMM"].as_str().unwrap_or("unknown");
    let message = v["MESSAGE"].as_str().unwrap_or("");
    let source = journald_source();

    // Check for auth events (sshd, sudo)
    if is_auth_comm(comm) {
        if let Some(auth) = try_parse_auth(comm, message) {
            return Ok(Some(NousEvent::new(
                time,
                3001,
                3,
                severity,
                source,
                EventPayload::Authentication(auth),
            )));
        }
    }

    // Check for process events
    if let Some(proc_evt) = try_parse_process(v, comm, message) {
        return Ok(Some(NousEvent::new(
            time,
            1001,
            1,
            severity,
            source,
            EventPayload::ProcessActivity(proc_evt),
        )));
    }

    // Default: SystemLog
    Ok(Some(NousEvent::new(
        time,
        0,
        0,
        severity,
        source,
        EventPayload::SystemLog(SystemLog {
            source_name: comm.to_string(),
            message: message.to_string(),
        }),
    )))
}

/// Parse __REALTIME_TIMESTAMP (microseconds since epoch) to nanoseconds.
fn parse_realtime_timestamp(v: &Value) -> Result<i64> {
    let ts_str = v["__REALTIME_TIMESTAMP"]
        .as_str()
        .ok_or_else(|| NousError::Normalization("missing __REALTIME_TIMESTAMP".into()))?;
    let us: i64 = ts_str
        .parse()
        .map_err(|_| NousError::Normalization(format!("invalid timestamp: {ts_str}")))?;
    Ok(us * 1000) // microseconds to nanoseconds
}

/// Map journald priority to Severity.
fn priority_to_severity(priority: u8) -> Severity {
    match priority {
        0..=2 => Severity::Critical, // emerg, alert, crit
        3 => Severity::High,         // err
        4 => Severity::Medium,       // warning
        5 => Severity::Low,          // notice
        6 => Severity::Info,         // info
        _ => Severity::Info,         // debug
    }
}

fn is_auth_comm(comm: &str) -> bool {
    matches!(comm, "sshd" | "sudo" | "login" | "su")
}

fn try_parse_auth(comm: &str, message: &str) -> Option<Authentication> {
    let msg_lower = message.to_lowercase();
    let protocol = match comm {
        "sshd" => AuthProtocol::Ssh,
        "sudo" | "su" | "login" => AuthProtocol::Local,
        _ => AuthProtocol::Unknown,
    };

    if msg_lower.contains("failed password") || msg_lower.contains("authentication failure") {
        let user = extract_user(message).unwrap_or("unknown");
        let src_ip = extract_ip(message);
        return Some(Authentication {
            user: user.to_string(),
            src: src_ip.map(|ip| Endpoint {
                ip,
                port: None,
                hostname: None,
                mac: None,
            }),
            auth_protocol: protocol,
            activity: AuthActivity::FailedLogin,
            status: AuthStatus::Failure,
        });
    }

    if msg_lower.contains("accepted password")
        || msg_lower.contains("accepted publickey")
        || msg_lower.contains("session opened")
    {
        let user = extract_user(message).unwrap_or("unknown");
        let src_ip = extract_ip(message);
        return Some(Authentication {
            user: user.to_string(),
            src: src_ip.map(|ip| Endpoint {
                ip,
                port: None,
                hostname: None,
                mac: None,
            }),
            auth_protocol: protocol,
            activity: AuthActivity::Login,
            status: AuthStatus::Success,
        });
    }

    None
}

fn try_parse_process(v: &Value, _comm: &str, message: &str) -> Option<ProcessActivity> {
    let cmdline = v["_CMDLINE"].as_str();
    let exe = v["_EXE"].as_str();

    // Only create ProcessActivity if we have cmdline or exe info AND process-lifecycle keywords
    if cmdline.is_none() && exe.is_none() {
        return None;
    }

    let msg_lower = message.to_lowercase();
    let action = if msg_lower.contains("started") || msg_lower.contains("starting") {
        ProcessAction::Start
    } else if msg_lower.contains("stopped")
        || msg_lower.contains("stopping")
        || msg_lower.contains("exited")
    {
        ProcessAction::Stop
    } else {
        return None;
    };

    Some(ProcessActivity {
        pid: v["_PID"].as_str().and_then(|s| s.parse().ok()),
        ppid: None,
        name: v["_COMM"].as_str().unwrap_or("unknown").to_string(),
        cmd_line: cmdline.map(String::from),
        user: v["_UID"].as_str().map(|u| format!("uid:{u}")),
        file_path: exe.map(String::from),
        action,
    })
}

fn extract_user(msg: &str) -> Option<&str> {
    if let Some(idx) = msg.find(" for ") {
        let after = &msg[idx + 5..];
        let after = after.strip_prefix("user ").unwrap_or(after);
        let after = after.strip_prefix("invalid user ").unwrap_or(after);
        return after.split_whitespace().next();
    }
    None
}

fn extract_ip(msg: &str) -> Option<std::net::IpAddr> {
    if let Some(idx) = msg.find(" from ") {
        let after = &msg[idx + 6..];
        return after.split_whitespace().next().and_then(|s| s.parse().ok());
    }
    None
}

fn journald_source() -> EventSource {
    EventSource {
        adapter: AdapterType::Journald,
        product: Some("journald".into()),
        sensor: None,
        original_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_journald_entry(comm: &str, message: &str) -> String {
        serde_json::json!({
            "__REALTIME_TIMESTAMP": "1705312201123456",
            "_COMM": comm,
            "MESSAGE": message,
            "PRIORITY": "6",
            "_PID": "1234",
            "_UID": "0"
        })
        .to_string()
    }

    #[test]
    fn basic_system_log() {
        let adapter = JournaldAdapter::new();
        let json = make_journald_entry("kernel", "some kernel message");
        let evt = adapter.parse_line(&json).unwrap().unwrap();
        assert_eq!(evt.class_uid, 0);
        match &evt.payload {
            EventPayload::SystemLog(s) => {
                assert_eq!(s.source_name, "kernel");
                assert_eq!(s.message, "some kernel message");
            }
            _ => panic!("expected SystemLog"),
        }
    }

    #[test]
    fn process_start() {
        let adapter = JournaldAdapter::new();
        let json = serde_json::json!({
            "__REALTIME_TIMESTAMP": "1705312201123456",
            "_COMM": "systemd",
            "MESSAGE": "Started nginx.service",
            "PRIORITY": "6",
            "_PID": "1",
            "_CMDLINE": "/usr/lib/systemd/systemd",
            "_EXE": "/usr/lib/systemd/systemd"
        })
        .to_string();
        let evt = adapter.parse_line(&json).unwrap().unwrap();
        assert_eq!(evt.class_uid, 1001);
        match &evt.payload {
            EventPayload::ProcessActivity(p) => {
                assert_eq!(p.action, ProcessAction::Start);
                assert_eq!(p.name, "systemd");
            }
            _ => panic!("expected ProcessActivity"),
        }
    }

    #[test]
    fn process_stop() {
        let adapter = JournaldAdapter::new();
        let json = serde_json::json!({
            "__REALTIME_TIMESTAMP": "1705312201123456",
            "_COMM": "systemd",
            "MESSAGE": "Stopped nginx.service",
            "PRIORITY": "6",
            "_PID": "1",
            "_CMDLINE": "/usr/lib/systemd/systemd",
            "_EXE": "/usr/lib/systemd/systemd"
        })
        .to_string();
        let evt = adapter.parse_line(&json).unwrap().unwrap();
        assert_eq!(evt.class_uid, 1001);
        match &evt.payload {
            EventPayload::ProcessActivity(p) => {
                assert_eq!(p.action, ProcessAction::Stop);
            }
            _ => panic!("expected ProcessActivity"),
        }
    }

    #[test]
    fn ssh_login() {
        let adapter = JournaldAdapter::new();
        let json = serde_json::json!({
            "__REALTIME_TIMESTAMP": "1705312201123456",
            "_COMM": "sshd",
            "MESSAGE": "Accepted publickey for admin from 10.0.0.50 port 22 ssh2",
            "PRIORITY": "6",
            "_PID": "5678"
        })
        .to_string();
        let evt = adapter.parse_line(&json).unwrap().unwrap();
        assert_eq!(evt.class_uid, 3001);
        match &evt.payload {
            EventPayload::Authentication(a) => {
                assert_eq!(a.user, "admin");
                assert_eq!(a.auth_protocol, AuthProtocol::Ssh);
                assert_eq!(a.activity, AuthActivity::Login);
                assert_eq!(a.status, AuthStatus::Success);
            }
            _ => panic!("expected Authentication"),
        }
    }

    #[test]
    fn ssh_failed_login() {
        let adapter = JournaldAdapter::new();
        let json = serde_json::json!({
            "__REALTIME_TIMESTAMP": "1705312201123456",
            "_COMM": "sshd",
            "MESSAGE": "Failed password for root from 10.0.0.99 port 22 ssh2",
            "PRIORITY": "4",
            "_PID": "5678"
        })
        .to_string();
        let evt = adapter.parse_line(&json).unwrap().unwrap();
        assert_eq!(evt.class_uid, 3001);
        match &evt.payload {
            EventPayload::Authentication(a) => {
                assert_eq!(a.user, "root");
                assert_eq!(a.activity, AuthActivity::FailedLogin);
                assert_eq!(a.status, AuthStatus::Failure);
                let src = a.src.as_ref().unwrap();
                assert_eq!(src.ip.to_string(), "10.0.0.99");
            }
            _ => panic!("expected Authentication"),
        }
    }

    #[test]
    fn priority_mapping() {
        assert_eq!(priority_to_severity(0), Severity::Critical);
        assert_eq!(priority_to_severity(2), Severity::Critical);
        assert_eq!(priority_to_severity(3), Severity::High);
        assert_eq!(priority_to_severity(4), Severity::Medium);
        assert_eq!(priority_to_severity(5), Severity::Low);
        assert_eq!(priority_to_severity(6), Severity::Info);
        assert_eq!(priority_to_severity(7), Severity::Info);
    }

    #[test]
    fn missing_timestamp_returns_error() {
        let adapter = JournaldAdapter::new();
        let json = serde_json::json!({
            "_COMM": "test",
            "MESSAGE": "hello"
        })
        .to_string();
        assert!(adapter.parse_line(&json).is_err());
    }

    #[test]
    fn malformed_json_returns_error() {
        let adapter = JournaldAdapter::new();
        assert!(adapter.parse_line("not json").is_err());
    }

    #[test]
    fn empty_line_returns_none() {
        let adapter = JournaldAdapter::new();
        assert!(adapter.parse_line("").unwrap().is_none());
    }

    #[test]
    fn system_log_serde_roundtrip() {
        let adapter = JournaldAdapter::new();
        let json = make_journald_entry("kernel", "test message");
        let evt = adapter.parse_line(&json).unwrap().unwrap();
        let serialized = serde_json::to_string(&evt).unwrap();
        let deser: NousEvent = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deser.class_uid, evt.class_uid);
    }

    #[test]
    fn auth_serde_roundtrip() {
        let adapter = JournaldAdapter::new();
        let json = serde_json::json!({
            "__REALTIME_TIMESTAMP": "1705312201123456",
            "_COMM": "sshd",
            "MESSAGE": "Accepted publickey for admin from 10.0.0.50 port 22 ssh2",
            "PRIORITY": "6",
            "_PID": "5678"
        })
        .to_string();
        let evt = adapter.parse_line(&json).unwrap().unwrap();
        let serialized = serde_json::to_string(&evt).unwrap();
        let deser: NousEvent = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deser.class_uid, 3001);
    }
}
