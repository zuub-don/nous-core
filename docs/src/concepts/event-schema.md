# Event Schema

Every event flowing through Nous Core is wrapped in a `NousEvent` envelope regardless of source or class.

## NousEvent Envelope

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID (v7) | Unique event identifier, time-ordered |
| `time` | i64 | Source timestamp (nanoseconds since epoch) |
| `ingest_time` | i64 | When Nous Core ingested the event (nanoseconds) |
| `class_uid` | u32 | OCSF event class identifier |
| `category_uid` | u16 | OCSF category identifier |
| `severity` | Severity | Severity level (0-5) |
| `source` | EventSource | Adapter type, product name, sensor ID |
| `payload` | EventPayload | Typed event data |
| `raw` | Option\<String\> | Original source line (optional, for audit) |

## OCSF Class Mapping

| class_uid | OCSF Name | category_uid | Payload Type |
|-----------|-----------|--------------|--------------|
| 1001 | Process Activity | 1 | `ProcessActivity` |
| 2004 | Detection Finding | 2 | `DetectionFinding` |
| 3001 | Authentication | 3 | `Authentication` |
| 4001 | Network Connection | 4 | `NetworkConnection` |
| 4002 | HTTP Activity | 4 | `HttpActivity` |
| 4003 | DNS Activity | 4 | `DnsActivity` |
| 4014 | TLS Activity | 4 | `TlsActivity` |
| 0 | Generic / SystemLog | 0 | `Generic` or `SystemLog` |

## EventPayload Variants

```rust
pub enum EventPayload {
    DnsActivity(DnsActivity),
    NetworkConnection(NetworkConnection),
    DetectionFinding(DetectionFinding),
    HttpActivity(HttpActivity),
    TlsActivity(TlsActivity),
    ProcessActivity(ProcessActivity),
    Authentication(Authentication),
    SystemLog(SystemLog),
    AgentAction(AgentAction),
    Verdict(Verdict),
    StateSnapshot(StateSnapshot),
    Generic(GenericEvent),
}
```

The payload is tagged with `"type"` in JSON serialization for unambiguous deserialization.

## Full JSON Example

```json
{
  "id": "01944abc-def0-7000-8000-000000000001",
  "time": 1705312201000000000,
  "ingest_time": 1705312201050000000,
  "class_uid": 4003,
  "category_uid": 4,
  "severity": "info",
  "source": {
    "adapter": "suricata",
    "product": "Suricata",
    "sensor": null,
    "original_id": null
  },
  "payload": {
    "type": "DnsActivity",
    "activity_id": 1,
    "query": {
      "hostname": "example.com",
      "type_id": 1,
      "class": 1,
      "transaction_uid": 12345
    },
    "response": null,
    "src": {
      "ip": "10.0.0.5",
      "port": 44123,
      "hostname": null
    },
    "dst": {
      "ip": "8.8.8.8",
      "port": 53,
      "hostname": null
    }
  }
}
```

## EventSource

| Field | Type | Description |
|-------|------|-------------|
| `adapter` | AdapterType | Source adapter (suricata, zeek, syslog, journald) |
| `product` | Option\<String\> | Tool name/version (e.g., "Suricata") |
| `sensor` | Option\<String\> | Hostname or sensor ID |
| `original_id` | Option\<String\> | Original event ID for dedup/correlation |
