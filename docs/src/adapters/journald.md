# Journald Adapter

The journald adapter parses JSON output from `journalctl -o json` into Nous Core events. It detects three categories of events:

- **Authentication** — sshd/sudo messages with login patterns
- **Process Activity** — entries with `_CMDLINE`/`_EXE` and lifecycle keywords
- **System Log** — everything else

## Input Format

Each line is a JSON object produced by `journalctl -o json`:

```json
{
  "__REALTIME_TIMESTAMP": "1705312201123456",
  "_COMM": "sshd",
  "MESSAGE": "Accepted publickey for admin from 10.0.0.50 port 22 ssh2",
  "PRIORITY": "6",
  "_PID": "5678",
  "_UID": "0",
  "_CMDLINE": "/usr/sbin/sshd -D",
  "_EXE": "/usr/sbin/sshd"
}
```

### Key Fields

| Field | Description |
|-------|-------------|
| `__REALTIME_TIMESTAMP` | Microseconds since epoch (required) |
| `_COMM` | Command name of the process |
| `MESSAGE` | Log message text |
| `PRIORITY` | Syslog-compatible priority (0-7) |
| `_PID` | Process ID |
| `_UID` | User ID |
| `_CMDLINE` | Full command line |
| `_EXE` | Executable path |

## Priority to Severity Mapping

Uses the same scale as syslog:

| Priority | Name | Nous Severity |
|----------|------|---------------|
| 0-2 | emerg/alert/crit | Critical (5) |
| 3 | err | High (4) |
| 4 | warning | Medium (3) |
| 5 | notice | Low (2) |
| 6 | info | Info (1) |
| 7 | debug | Info (1) |

## Authentication Heuristic

Messages from `sshd`, `sudo`, `login`, and `su` are checked for auth patterns:

| Pattern | Activity | Status |
|---------|----------|--------|
| "Failed password" / "authentication failure" | FailedLogin | Failure |
| "Accepted password" / "Accepted publickey" / "session opened" | Login | Success |

## Process Heuristic

Entries with `_CMDLINE` or `_EXE` fields are checked for lifecycle keywords:

| Message Keyword | Process Action |
|----------------|----------------|
| "started" / "starting" | Start |
| "stopped" / "stopping" / "exited" | Stop |

If no lifecycle keyword is found, the entry falls through to `SystemLog`.

## Examples

### SSH Login

Input:

```json
{
  "__REALTIME_TIMESTAMP": "1705312201123456",
  "_COMM": "sshd",
  "MESSAGE": "Accepted publickey for admin from 10.0.0.50 port 22 ssh2",
  "PRIORITY": "6",
  "_PID": "5678"
}
```

Produces an `Authentication` event (class_uid 3001).

### Process Start

Input:

```json
{
  "__REALTIME_TIMESTAMP": "1705312201123456",
  "_COMM": "systemd",
  "MESSAGE": "Started nginx.service",
  "PRIORITY": "6",
  "_PID": "1",
  "_CMDLINE": "/usr/lib/systemd/systemd",
  "_EXE": "/usr/lib/systemd/systemd"
}
```

Produces a `ProcessActivity` event (class_uid 1001) with `action: Start`.

### System Log Fallback

Input:

```json
{
  "__REALTIME_TIMESTAMP": "1705312201123456",
  "_COMM": "kernel",
  "MESSAGE": "some kernel message",
  "PRIORITY": "6",
  "_PID": "0"
}
```

Produces a `SystemLog` event (class_uid 0).

## Usage

```bash
# Stream live journal entries
journalctl -f -o json | nous-engine --adapter journald

# Replay from a saved journal export
nous-engine --input journal-export.json --adapter journald
```
