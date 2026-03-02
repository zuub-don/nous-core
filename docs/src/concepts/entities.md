# Entities

Entities are security-relevant objects tracked across events. The semantic state engine auto-extracts entities from events and maintains metadata about each one.

## Entity Types

| Type | Example | Description |
|------|---------|-------------|
| `ip_address` | `10.0.0.1` | IPv4 or IPv6 address |
| `domain` | `evil.com` | Domain name |
| `hostname` | `workstation-42` | Host name |
| `user` | `root` | Username |
| `process` | `sshd` | Process name |
| `file` | `/tmp/malware.exe` | File path |
| `url` | `https://evil.com/c2` | URL |

## Entity Metadata

Each tracked entity has associated metadata:

| Field | Type | Description |
|-------|------|-------------|
| `risk_score` | u8 (0-100) | Current risk assessment |
| `first_seen` | i64 | Timestamp of first event referencing this entity |
| `last_seen` | i64 | Timestamp of most recent event |
| `hit_count` | u64 | Total number of events referencing this entity |

## Auto-Extraction Rules

Entities are automatically extracted from event payloads:

| Event Type | Extracted Entities |
|------------|-------------------|
| `DnsActivity` | src IP, dst IP, query domain |
| `NetworkConnection` | src IP, dst IP |
| `HttpActivity` | src IP, dst IP |
| `TlsActivity` | src IP, dst IP, server name (as domain) |
| `Authentication` | user, src IP (if present) |
| `DetectionFinding` | entities list from the finding |

## Risk Scores

Risk scores range from 0 (no risk) to 100 (maximum risk). They are updated by:

- **Verdict feedback** — verdicts adjust risk scores of entities associated with findings
- **Manual updates** — the `update_entity_risk()` API sets a score directly
- **Risk adjustments** — `adjust_entity_risk()` applies a signed delta, clamped to 0-100

## Querying Entities

### CLI

```bash
nous-ctl entity ip_address 10.0.0.1
```

### MCP

```json
{"name": "query_entity", "arguments": {"entity_type": "ip_address", "value": "10.0.0.1"}}
```

## Top Entities

The `observe` tool and context windows include a ranked list of top entities by risk score. This gives AI agents immediate visibility into the highest-risk entities in the environment.
