# nous-ctl observe

Generate a context window — a token-budgeted summary of the current security situation designed for LLM consumption.

## Usage

```
nous-ctl observe [OPTIONS]
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--budget <N>` | `4096` | Token budget (0 = server default) |
| `--format <F>` | *(server default: structured_json)* | Output format |

### Format Values

| Format | Description |
|--------|-------------|
| `structured_json` | Machine-readable JSON sections for tool-use agents |
| `narrative` | Natural language summary for chat-based agents |
| `delta` | Changes since last observation |

## Examples

```bash
# Default: structured JSON, 4096 tokens
nous-ctl observe

# Narrative format
nous-ctl observe --format narrative

# Large context window
nous-ctl observe --budget 16384

# Delta report
nous-ctl observe --format delta --budget 2048
```

## Output: structured_json

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
    "critical_findings": [
      "[HIGH] ET MALWARE Known Bad C2 Channel"
    ],
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

## Output: narrative

```
Security situation as of now: 1247 events ingested, 3 active findings.
Severity breakdown: 7 critical, 10 high, 30 medium, 100 low, 1100 info.
42 entities tracked. Top threat: 10.0.0.99 (IpAddress, risk 85).
```

## Output: delta

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
