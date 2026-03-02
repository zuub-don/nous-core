# query_events

Query recent security events with optional filters.

## Parameters

All parameters are optional.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `class_uid` | integer | `0` (all) | OCSF class UID filter |
| `min_severity` | integer | `0` (all) | Minimum severity level (0-5) |
| `limit` | integer | `100` | Maximum events to return |

## Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `events` | array | Array of event objects |
| `total` | integer | Total matching events (may exceed limit) |

## Example

Request:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "query_events",
    "arguments": {
      "class_uid": 2004,
      "min_severity": 4,
      "limit": 10
    }
  }
}
```

Parsed tool result:

```json
{
  "events": [
    {
      "id": "01944abc-...",
      "time": 1705312201000000000,
      "class_uid": 2004,
      "severity": "high",
      "payload": {
        "type": "DetectionFinding",
        "title": "ET MALWARE Known Bad C2 Channel",
        "risk_score": 80,
        "risk_level": "high",
        "status": "new"
      }
    }
  ],
  "total": 1
}
```
