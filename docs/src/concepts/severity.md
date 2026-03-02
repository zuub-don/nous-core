# Severity

Nous Core uses a 6-level severity scale aligned with OCSF severity IDs.

## Severity Levels

| ID | Name | Label | Description |
|----|------|-------|-------------|
| 0 | Unknown | UNKN | Severity not determined |
| 1 | Info | INFO | Informational, no action needed |
| 2 | Low | LOW | Minor issue, low priority |
| 3 | Medium | MED | Moderate issue, should be reviewed |
| 4 | High | HIGH | Significant issue, requires attention |
| 5 | Critical | CRIT | Critical issue, immediate action required |

Severity values are ordered: `Unknown < Info < Low < Medium < High < Critical`.

## Adapter Severity Mappings

### Suricata

Suricata alerts include a `severity` field (actually a priority, 1 = highest):

| Suricata Priority | Nous Severity |
|-------------------|---------------|
| 1 | High (4) |
| 2 | Medium (3) |
| 3 | Low (2) |
| 4+ | Info (1) |

Non-alert Suricata events (DNS, flow, HTTP, TLS) default to Info.

### Syslog

Syslog priority encodes `facility * 8 + severity`. The low 3 bits determine severity:

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

### Journald

Journald uses the same priority scale as syslog (0-7 in the `PRIORITY` field).

### Zeek

Zeek events default to Info severity. Notice log entries (similar to alerts) are assigned Medium severity.

## Usage in Filtering

The `--severity` flag in `nous-ctl` and the `min_severity` parameter in MCP tools filter events with severity **at or above** the specified level:

```bash
# Show High (4) and Critical (5) events only
nous-ctl events --severity 4
```
