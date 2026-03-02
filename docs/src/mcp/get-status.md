# get_status

Get the current engine status: event count, active findings, uptime, and version.

## Parameters

None.

## Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `event_count` | integer | Total events ingested since engine startup |
| `active_findings` | integer | Detection findings awaiting triage |
| `uptime_seconds` | integer | Seconds since the engine started |
| `version` | string | Engine version string |

## Example

Request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_status",
    "arguments": {}
  }
}
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{
      "type": "text",
      "text": "{\n  \"event_count\": 1247,\n  \"active_findings\": 3,\n  \"uptime_seconds\": 42,\n  \"version\": \"0.1.0\"\n}"
    }]
  }
}
```

Parsed tool result:

```json
{
  "event_count": 1247,
  "active_findings": 3,
  "uptime_seconds": 42,
  "version": "0.1.0"
}
```
