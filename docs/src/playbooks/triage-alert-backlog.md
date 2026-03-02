# Triage Alert Backlog

Work through pending security findings, assessing each and submitting verdicts.

## When to Use

- Active findings count is non-zero in `get_status`
- Routine triage during a shift handoff or scheduled review

## Workflow

### 1. Get Situational Awareness

Call `observe` to understand the current state:

```json
{"name": "observe", "arguments": {"format": "structured_json"}}
```

Note the `active_findings` count and severity distribution.

### 2. Pull Detection Findings

Query for detection events (OCSF class 2004):

```json
{"name": "query_events", "arguments": {"class_uid": 2004, "limit": 20}}
```

### 3. For Each Finding: Investigate

For each finding, examine the associated entities:

```json
{"name": "query_entity", "arguments": {"entity_type": "ip_address", "value": "<src_ip>"}}
```

Check the `risk_score`, `hit_count`, and `co_occurrences` to understand context. High co-occurrence with known-bad entities raises confidence.

### 4. Submit Verdict

Based on your assessment:

```json
{
  "name": "submit_verdict",
  "arguments": {
    "finding_id": "<uuid>",
    "verdict": "true_positive",
    "agent_id": "triage-agent",
    "reasoning": "Source IP has risk_score 85 and co-occurs with known C2 domain evil.com across 23 events.",
    "confidence": 0.9
  }
}
```

### 5. Repeat

Continue until all findings are triaged or the agent's confidence drops below threshold.

## Verdict Guide

| Verdict | When |
|---------|------|
| `true_positive` | Confirmed malicious activity |
| `false_positive` | Benign activity misidentified as threat |
| `benign` | Activity is expected/authorized |
| `needs_investigation` | Insufficient data to decide |
