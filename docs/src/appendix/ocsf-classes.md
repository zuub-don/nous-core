# OCSF Class Reference

Nous Core uses [OCSF](https://ocsf.io/) (Open Cybersecurity Schema Framework) class UIDs to categorize events. This table lists all classes currently supported.

## Class UID Reference

| class_uid | OCSF Name | category_uid | Category | Adapters |
|-----------|-----------|--------------|----------|----------|
| 1001 | Process Activity | 1 | System Activity | journald |
| 2004 | Detection Finding | 2 | Findings | suricata, zeek |
| 3001 | Authentication | 3 | Identity & Access | syslog, journald |
| 4001 | Network Connection | 4 | Network Activity | suricata, zeek |
| 4002 | HTTP Activity | 4 | Network Activity | suricata, zeek |
| 4003 | DNS Activity | 4 | Network Activity | suricata, zeek |
| 4014 | TLS Activity | 4 | Network Activity | suricata, zeek |
| 0 | Generic / SystemLog | 0 | Uncategorized | all (fallback) |

## Category Summary

| category_uid | Category Name | Classes |
|--------------|--------------|---------|
| 0 | Uncategorized | Generic, SystemLog |
| 1 | System Activity | Process Activity |
| 2 | Findings | Detection Finding |
| 3 | Identity & Access | Authentication |
| 4 | Network Activity | Network Connection, HTTP, DNS, TLS |

## Usage in Filtering

Use `class_uid` values when filtering events:

```bash
# CLI: only detection findings
nous-ctl events --class 2004

# CLI: stream DNS events
nous-ctl watch --class 4003
```

```json
// MCP: query authentication events
{"name": "query_events", "arguments": {"class_uid": 3001}}
```

A `class_uid` of `0` matches all classes (no filter).
