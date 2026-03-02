# Syslog Adapter

The syslog adapter parses BSD-style syslog messages (RFC 5424) into Nous Core events. Authentication-related messages from `sshd`, `sudo`, `login`, and `su` are mapped to `Authentication` events; everything else becomes `SystemLog`.

## Input Format

Standard BSD syslog with optional priority prefix:

```
<PRI>Mon DD HH:MM:SS hostname app[pid]: message
```

Examples:

```
<38>Jan 15 10:30:00 host1 sshd[1234]: Failed password for root from 10.0.0.50 port 22
<14>Jan 15 10:30:00 host1 cron[999]: starting daily backup
```

Lines without a `<PRI>` prefix are accepted with a default priority of 13 (user.notice).

## Priority to Severity Mapping

The syslog priority encodes both facility and severity: `priority = facility * 8 + severity`. The low 3 bits determine severity:

| Syslog Severity (bits 0-2) | Name | Nous Severity |
|----------------------------|------|---------------|
| 0 | Emergency | Critical (5) |
| 1 | Alert | Critical (5) |
| 2 | Critical | Critical (5) |
| 3 | Error | High (4) |
| 4 | Warning | Medium (3) |
| 5 | Notice | Low (2) |
| 6 | Informational | Info (1) |
| 7 | Debug | Info (1) |

## Authentication Heuristic

Messages from these applications are checked for auth patterns:

| App Name | Auth Protocol |
|----------|--------------|
| `sshd` | SSH |
| `sudo` | Local |
| `login` | Local |
| `su` | Local |

### Pattern Detection

| Message Pattern | Activity | Status |
|----------------|----------|--------|
| "Failed password" or "authentication failure" | FailedLogin | Failure |
| "Accepted password", "Accepted publickey", or "session opened" | Login | Success |

The adapter extracts the username from `for <user>` patterns and the source IP from `from <ip>` patterns.

## Examples

### SSH Failed Login

Input:

```
<38>Jan 15 10:30:00 host1 sshd[1234]: Failed password for root from 10.0.0.50 port 22
```

Produces an `Authentication` event (class_uid 3001) with:
- `user`: "root"
- `auth_protocol`: SSH
- `activity`: FailedLogin
- `status`: Failure
- `src.ip`: 10.0.0.50

### Generic System Log

Input:

```
<14>Jan 15 10:30:00 host1 cron[999]: starting daily backup
```

Produces a `SystemLog` event (class_uid 0) with:
- `source_name`: "cron"
- `message`: "starting daily backup"

## Usage

```bash
nous-engine --input /var/log/syslog --adapter syslog

# Or pipe from a log file
tail -f /var/log/auth.log | nous-engine --adapter syslog
```
