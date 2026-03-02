# observe

Generate a context window summarizing the current security situation. This is the primary tool for AI agents to understand what's happening.

## Parameters

All parameters are optional.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `token_budget` | integer | `4096` | Token budget for the context window |
| `format` | string | `"structured_json"` | Output format |

### Token Budget Presets

| Budget | Name | Use Case |
|--------|------|----------|
| 1024 | Tiny | Quick status checks |
| 2048 | Small | Brief summaries |
| 4096 | Medium | Standard analysis (default) |
| 8192 | Large | Detailed investigation |
| 16384 | XLarge | Full situational awareness |

### Format Options

| Format | Description |
|--------|-------------|
| `structured_json` | Machine-readable JSON with sections for findings, entities, and baseline |
| `narrative` | Natural language summary for chat-based agents |
| `delta` | Changes since the last observation |

## Example: structured_json

Request:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "observe",
    "arguments": {
      "token_budget": 4096,
      "format": "structured_json"
    }
  }
}
```

Parsed tool result:

```json
{
  "generated_at": 1705312260000000000,
  "token_budget": 4096,
  "estimated_tokens": 312,
  "format": "structured_json",
  "summary": {
    "total_events": 1247,
    "active_findings": 3,
    "top_classes": [[4003, 800], [4001, 300], [2004, 10]],
    "severity_histogram": [0, 1100, 100, 30, 10, 7],
    "entity_count": 42
  },
  "content": {
    "content_type": "StructuredJson",
    "critical_findings": ["[HIGH] ET MALWARE Known Bad C2 Channel"],
    "top_entities": [
      {"entity_type": "ip_address", "value": "10.0.0.99", "risk_score": 85, "hit_count": 47}
    ],
    "baseline": {
      "severity_distribution": [0, 1100, 100, 30, 10, 7],
      "top_classes": [[4003, 800], [4001, 300]]
    }
  }
}
```

## Example: narrative

```json
{"token_budget": 2048, "format": "narrative"}
```

Result:

```
Security situation as of now: 1247 events ingested, 3 active findings.
Severity breakdown: 7 critical, 10 high, 30 medium, 100 low, 1100 info.
42 entities tracked. Top threat: 10.0.0.99 (IpAddress, risk 85).
```

## Example: delta

```json
{"token_budget": 2048, "format": "delta"}
```

Result:

```json
{
  "content_type": "Delta",
  "new_findings": 2,
  "resolved_findings": 0,
  "new_entities": 5,
  "risk_changes": [
    {"entity_type": "ip_address", "value": "10.0.0.99", "old_score": 60, "new_score": 85}
  ],
  "text": "Delta: 2 new findings, 0 resolved, 5 new entities, 1 risk changes."
}
```
