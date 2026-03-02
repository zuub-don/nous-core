# Adapters Overview

Adapters convert raw security telemetry from different sources into normalized `NousEvent` structs. Each adapter implements the `Adapter` trait with a single method:

```rust
fn parse_line(&self, line: &str) -> Result<Option<NousEvent>>;
```

## Available Adapters

| Adapter | Input Format | OCSF Classes Produced | Source Tool |
|---------|-------------|----------------------|-------------|
| [Suricata](suricata.md) | EVE JSON (NDJSON) | 2004, 4001, 4002, 4003, 4014 | Suricata IDS/IPS |
| [Zeek](zeek.md) | Tab-separated with `#path`/`#fields` headers | 2004, 4001, 4002, 4003, 4014 | Zeek network monitor |
| [Syslog](syslog.md) | RFC 5424 `<PRI>` format | 3001, 0 (SystemLog) | rsyslog, syslog-ng |
| [Journald](journald.md) | `journalctl -o json` | 1001, 3001, 0 (SystemLog) | systemd-journald |

## Adapter Selection

Specify the adapter with `--adapter` when starting `nous-engine`:

```bash
nous-engine --adapter suricata --input /var/log/suricata/eve.json
```

The `auto` adapter (default) attempts to detect the format from the first line of input.

## OCSF Class Summary

| class_uid | OCSF Name | Produced By |
|-----------|-----------|-------------|
| 1001 | Process Activity | journald |
| 2004 | Detection Finding | suricata, zeek |
| 3001 | Authentication | syslog, journald |
| 4001 | Network Connection | suricata, zeek |
| 4002 | HTTP Activity | suricata, zeek |
| 4003 | DNS Activity | suricata, zeek |
| 4014 | TLS Activity | suricata, zeek |
| 0 | Generic/SystemLog | all (fallback) |

## Common Behaviors

- Empty lines and whitespace-only lines return `None` (skipped)
- Malformed input returns an error
- Unrecognized event types are preserved as `Generic` events with `class_uid: 0`
- All adapters attach an `EventSource` with the adapter type and product name
