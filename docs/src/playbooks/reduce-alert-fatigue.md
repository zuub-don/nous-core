# Reduce Alert Fatigue

Identify repeated low-confidence alerts and suppress noisy rules.

## When to Use

- High event counts with few true positives
- Analysts report excessive false positives from specific rules
- Routine tuning during quiet periods

## Workflow

### 1. Observe Current State

Get a high-level view:

```json
{"name": "observe", "arguments": {"format": "structured_json"}}
```

Look at the class counts and severity histogram. High counts of low-severity events suggest noise.

### 2. Query Low-Severity Events

Pull detection findings at low severity:

```json
{"name": "query_events", "arguments": {"class_uid": 2004, "min_severity": 1, "limit": 50}}
```

### 3. Identify Patterns

Look for:
- Repeated rule UIDs firing on the same entities
- Low-risk entities generating many alerts
- Known-benign activity triggering detections

### 4. Verdict Repeated False Positives

For alerts confirmed as noise:

```json
{
  "name": "submit_verdict",
  "arguments": {
    "finding_id": "<uuid>",
    "verdict": "false_positive",
    "agent_id": "tuning-agent",
    "reasoning": "Scanner traffic from monitoring host 10.0.0.5. Entity risk_score is 0 with 200+ hits, all benign.",
    "confidence": 0.95
  }
}
```

### 5. Suppress Noisy Rules

For rules that consistently produce false positives:

```json
{
  "name": "submit_action",
  "arguments": {
    "action_type": "suppress",
    "agent_id": "tuning-agent",
    "target_entity_type": "ip_address",
    "target_value": "10.0.0.5",
    "reasoning": "Monitoring host generates 50+ false positive detections per hour. Suppressing to reduce noise."
  }
}
```

### 6. Verify Improvement

After suppression, call `observe` again to confirm the noise reduction without losing visibility on real threats.

## Guidelines

- Only suppress after confirming the pattern across multiple events
- Always provide detailed reasoning for audit trail
- Re-evaluate suppressions periodically — threats evolve
