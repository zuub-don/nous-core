//! RFC 5424 syslog adapter.
//!
//! Parses syslog messages into Nous Core events. Auth-related messages
//! from sshd/sudo/login are mapped to Authentication events; everything
//! else becomes SystemLog.

use nous_core::error::{NousError, Result};
use nous_core::event::{
    AdapterType, AuthActivity, AuthProtocol, AuthStatus, Authentication, Endpoint, EventPayload,
    EventSource, NousEvent, SystemLog,
};
use nous_core::severity::Severity;

use crate::Adapter;

/// Syslog adapter (RFC 5424-style).
pub struct SyslogAdapter;

impl SyslogAdapter {
    /// Create a new syslog adapter.
    pub fn new() -> Self {
        Self
    }
}

impl Default for SyslogAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for SyslogAdapter {
    fn name(&self) -> &'static str {
        "syslog"
    }

    fn parse_line(&self, line: &str) -> Result<Option<NousEvent>> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(None);
        }

        parse_syslog_line(line)
    }
}

/// Parse a syslog line. Supports BSD-style: <PRI>TIMESTAMP HOSTNAME APP[PID]: MSG
fn parse_syslog_line(line: &str) -> Result<Option<NousEvent>> {
    let (priority, rest) = parse_priority(line)?;
    let severity = priority_to_severity(priority);

    // BSD syslog: "Mon DD HH:MM:SS hostname app[pid]: message"
    // After priority strip, rest looks like: "Jan 15 10:30:00 host1 sshd[1234]: msg"
    // We need to skip the 3-token timestamp, then hostname, then parse app: msg
    let tokens: Vec<&str> = rest.splitn(6, ' ').collect();
    if tokens.len() < 5 {
        return Err(NousError::Normalization("syslog line too short".into()));
    }

    // tokens: [month, day, time, hostname, "app[pid]:", "rest of message"]
    // or:     [month, day, time, hostname, "app[pid]: rest of message"]
    let app_token = tokens[4];
    let (app_name, msg_start) = if let Some(colon_pos) = app_token.find(':') {
        let app_part = &app_token[..colon_pos];
        let app_clean = app_part.split('[').next().unwrap_or(app_part);
        let msg_in_token = app_token[colon_pos + 1..].trim_start();
        (app_clean, msg_in_token)
    } else {
        let app_clean = app_token.split('[').next().unwrap_or(app_token);
        (app_clean, "")
    };

    // Combine remaining message
    let message = if tokens.len() > 5 {
        if msg_start.is_empty() {
            tokens[5].to_string()
        } else {
            format!("{} {}", msg_start, tokens[5])
        }
    } else {
        msg_start.to_string()
    };

    let time = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let source = syslog_source();

    // Check if this is an auth event
    if is_auth_app(app_name) {
        if let Some(auth) = try_parse_auth(app_name, &message) {
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

    // Default: SystemLog
    Ok(Some(NousEvent::new(
        time,
        0,
        0,
        severity,
        source,
        EventPayload::SystemLog(SystemLog {
            source_name: app_name.to_string(),
            message,
        }),
    )))
}

/// Parse the priority value from <PRI>.
fn parse_priority(line: &str) -> Result<(u8, &str)> {
    if !line.starts_with('<') {
        // No priority prefix — treat entire line as message with default priority
        return Ok((13, line)); // 13 = facility user (1) * 8 + severity notice (5)
    }
    let end = line
        .find('>')
        .ok_or_else(|| NousError::Normalization("malformed syslog priority".into()))?;
    let pri: u8 = line[1..end]
        .parse()
        .map_err(|_| NousError::Normalization("invalid priority value".into()))?;
    Ok((pri, &line[end + 1..]))
}

/// Map syslog priority to Severity.
/// Priority = facility * 8 + severity. Severity is bits 0-2.
fn priority_to_severity(priority: u8) -> Severity {
    let syslog_sev = priority & 0x07;
    match syslog_sev {
        0..=2 => Severity::Critical, // emerg, alert, crit
        3 => Severity::High,         // error
        4 => Severity::Medium,       // warning
        5 => Severity::Low,          // notice
        6 => Severity::Info,         // info
        _ => Severity::Info,         // debug
    }
}

/// Check if this app name is auth-related.
fn is_auth_app(app_name: &str) -> bool {
    matches!(
        app_name.to_lowercase().as_str(),
        "sshd" | "sudo" | "login" | "su"
    )
}

/// Try to parse an Authentication event from an auth app's message.
fn try_parse_auth(app_name: &str, message: &str) -> Option<Authentication> {
    let msg_lower = message.to_lowercase();
    let app_lower = app_name.to_lowercase();

    let protocol = match app_lower.as_str() {
        "sshd" => AuthProtocol::Ssh,
        "sudo" | "su" | "login" => AuthProtocol::Local,
        _ => AuthProtocol::Unknown,
    };

    if msg_lower.contains("failed password") || msg_lower.contains("authentication failure") {
        let user = extract_user_from_message(message).unwrap_or("unknown");
        let src_ip = extract_ip_from_message(message);
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
        let user = extract_user_from_message(message).unwrap_or("unknown");
        let src_ip = extract_ip_from_message(message);
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

/// Extract username from common syslog auth message patterns.
fn extract_user_from_message(msg: &str) -> Option<&str> {
    // "Failed password for <user> from ..."
    // "Accepted password for <user> from ..."
    // "session opened for user <user>"
    if let Some(idx) = msg.find(" for ") {
        let after = &msg[idx + 5..];
        let after = after.strip_prefix("user ").unwrap_or(after);
        let after = after.strip_prefix("invalid user ").unwrap_or(after);
        return after.split_whitespace().next();
    }
    None
}

/// Extract IP address from common syslog messages.
fn extract_ip_from_message(msg: &str) -> Option<std::net::IpAddr> {
    if let Some(idx) = msg.find(" from ") {
        let after = &msg[idx + 6..];
        return after.split_whitespace().next().and_then(|s| s.parse().ok());
    }
    None
}

fn syslog_source() -> EventSource {
    EventSource {
        adapter: AdapterType::Syslog,
        product: Some("syslog".into()),
        sensor: None,
        original_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_syslog_parse() {
        let adapter = SyslogAdapter::new();
        let evt = adapter
            .parse_line("<13>Jan 15 10:30:00 host1 kernel: some message")
            .unwrap()
            .unwrap();
        match &evt.payload {
            EventPayload::SystemLog(s) => {
                assert_eq!(s.source_name, "kernel");
            }
            _ => panic!("expected SystemLog"),
        }
    }

    #[test]
    fn severity_mapping_from_priority() {
        // priority 0 = emerg -> Critical (syslog_sev = 0)
        assert_eq!(priority_to_severity(0), Severity::Critical);
        // priority 3 = error -> High (syslog_sev = 3)
        assert_eq!(priority_to_severity(3), Severity::High);
        // priority 4 = warning -> Medium
        assert_eq!(priority_to_severity(4), Severity::Medium);
        // priority 5 = notice -> Low
        assert_eq!(priority_to_severity(5), Severity::Low);
        // priority 6 = info -> Info
        assert_eq!(priority_to_severity(6), Severity::Info);
        // priority 14 = facility 1 + sev 6 (info)
        assert_eq!(priority_to_severity(14), Severity::Info);
    }

    #[test]
    fn ssh_failed_login_to_authentication() {
        let adapter = SyslogAdapter::new();
        let evt = adapter
            .parse_line("<38>Jan 15 10:30:00 host1 sshd[1234]: Failed password for root from 10.0.0.50 port 22")
            .unwrap()
            .unwrap();
        assert_eq!(evt.class_uid, 3001);
        match &evt.payload {
            EventPayload::Authentication(a) => {
                assert_eq!(a.user, "root");
                assert_eq!(a.auth_protocol, AuthProtocol::Ssh);
                assert_eq!(a.activity, AuthActivity::FailedLogin);
                assert_eq!(a.status, AuthStatus::Failure);
                assert!(a.src.is_some());
            }
            _ => panic!("expected Authentication"),
        }
    }

    #[test]
    fn ssh_accepted_login_to_authentication() {
        let adapter = SyslogAdapter::new();
        let evt = adapter
            .parse_line("<38>Jan 15 10:30:00 host1 sshd[1234]: Accepted publickey for admin from 10.0.0.50 port 22")
            .unwrap()
            .unwrap();
        assert_eq!(evt.class_uid, 3001);
        match &evt.payload {
            EventPayload::Authentication(a) => {
                assert_eq!(a.user, "admin");
                assert_eq!(a.activity, AuthActivity::Login);
                assert_eq!(a.status, AuthStatus::Success);
            }
            _ => panic!("expected Authentication"),
        }
    }

    #[test]
    fn sudo_session_to_authentication() {
        let adapter = SyslogAdapter::new();
        let evt = adapter
            .parse_line("<86>Jan 15 10:30:00 host1 sudo[5678]: pam_unix(sudo:session): session opened for user root")
            .unwrap()
            .unwrap();
        assert_eq!(evt.class_uid, 3001);
        match &evt.payload {
            EventPayload::Authentication(a) => {
                assert_eq!(a.user, "root");
                assert_eq!(a.auth_protocol, AuthProtocol::Local);
                assert_eq!(a.activity, AuthActivity::Login);
            }
            _ => panic!("expected Authentication"),
        }
    }

    #[test]
    fn generic_syslog_to_system_log() {
        let adapter = SyslogAdapter::new();
        let evt = adapter
            .parse_line("<14>Jan 15 10:30:00 host1 cron[999]: starting daily backup")
            .unwrap()
            .unwrap();
        assert_eq!(evt.class_uid, 0);
        match &evt.payload {
            EventPayload::SystemLog(s) => {
                assert_eq!(s.source_name, "cron");
                assert!(s.message.contains("starting daily backup"));
            }
            _ => panic!("expected SystemLog"),
        }
    }

    #[test]
    fn empty_line_returns_none() {
        let adapter = SyslogAdapter::new();
        assert!(adapter.parse_line("").unwrap().is_none());
    }

    #[test]
    fn no_priority_prefix() {
        let adapter = SyslogAdapter::new();
        let evt = adapter
            .parse_line("Jan 15 10:30:00 host1 kernel: test message here")
            .unwrap()
            .unwrap();
        match &evt.payload {
            EventPayload::SystemLog(s) => {
                assert_eq!(s.source_name, "kernel");
                assert!(s.message.contains("test message here"));
            }
            _ => panic!("expected SystemLog"),
        }
    }

    #[test]
    fn malformed_priority() {
        let adapter = SyslogAdapter::new();
        let result = adapter.parse_line("<abc>rest of line");
        assert!(result.is_err());
    }

    #[test]
    fn syslog_serde_roundtrip() {
        let adapter = SyslogAdapter::new();
        let evt = adapter
            .parse_line("<14>Jan 15 10:30:00 host1 test[1]: message")
            .unwrap()
            .unwrap();
        let json = serde_json::to_string(&evt).unwrap();
        let deser: NousEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.class_uid, evt.class_uid);
    }

    #[test]
    fn auth_serde_roundtrip() {
        let adapter = SyslogAdapter::new();
        let evt = adapter
            .parse_line("<38>Jan 15 10:30:00 host1 sshd[1234]: Failed password for root from 10.0.0.50 port 22")
            .unwrap()
            .unwrap();
        let json = serde_json::to_string(&evt).unwrap();
        let deser: NousEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.class_uid, 3001);
    }
}
