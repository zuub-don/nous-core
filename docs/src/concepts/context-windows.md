# Context Windows

Context windows are token-budgeted situation reports generated from the semantic state. They are the primary way AI agents understand the current security situation.

## Purpose

LLMs have finite context windows. Rather than dumping raw events into a prompt, Nous Core compresses the semantic state into a structured report that fits within a specified token budget. This gives agents maximum situational awareness per token.

## Token Budget Presets

| Budget | Name | Approximate Size | Use Case |
|--------|------|-----------------|----------|
| 1,024 | Tiny | ~4 KB | Quick status checks |
| 2,048 | Small | ~8 KB | Brief summaries |
| 4,096 | Medium | ~16 KB | Standard analysis (default) |
| 8,192 | Large | ~32 KB | Detailed investigation |
| 16,384 | XLarge | ~64 KB | Full situational awareness |

Token estimation uses a ~4 characters per token heuristic.

## Output Formats

### structured_json

Machine-readable JSON with distinct sections. Best for tool-use agents that parse structured data.

```json
{
  "generated_at": 1705312260000000000,
  "token_budget": 4096,
  "estimated_tokens": 312,
  "format": "structured_json",
  "summary": {
    "total_events": 1247,
    "active_findings": 3,
    "top_classes": [[4003, 800], [4001, 300]],
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

### narrative

Natural language summary. Best for chat-based agents that work with prose.

```
Security situation as of now: 1247 events ingested, 3 active findings.
Severity breakdown: 7 critical, 10 high, 30 medium, 100 low, 1100 info.
42 entities tracked. Top threat: 10.0.0.99 (IpAddress, risk 85).
```

### delta

Changes since the last observation. Best for agents that poll periodically and need to understand what's new.

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

The delta format tracks the previous state internally. The first call returns baseline data; subsequent calls show differences.

## Summary Section

Every context window includes a summary regardless of format:

| Field | Description |
|-------|-------------|
| `total_events` | Total events ingested |
| `active_findings` | Findings awaiting triage |
| `top_classes` | Most common OCSF classes by count |
| `severity_histogram` | Event count per severity level (indices 0-5) |
| `entity_count` | Number of tracked entities |

## Token Estimation

Tokens are estimated from the serialized JSON using a byte-ratio heuristic:

```
estimated_tokens = json_bytes / 4
```

The generated content is capped at the token budget. Larger budgets allow more detail (more entities, more findings, more baseline data).
