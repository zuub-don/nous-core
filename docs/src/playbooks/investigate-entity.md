# Investigate Entity

Deep-dive into a specific entity to understand its behavior, relationships, and risk.

## When to Use

- An entity appears in a finding and needs investigation
- An entity's risk score is elevated but context is unclear
- Pivoting from another investigation to understand a related entity

## Workflow

### 1. Query the Entity

Start with a direct lookup:

```json
{"name": "query_entity", "arguments": {"entity_type": "ip_address", "value": "10.0.0.42"}}
```

Review the response:
- `risk_score` — current risk assessment
- `hit_count` — activity volume
- `first_seen` / `last_seen` — time window of activity
- `co_occurrences` — related entities sorted by shared event count

### 2. Pivot Through Neighbors

For each co-occurring entity, query it to build context:

```json
{"name": "query_entity", "arguments": {"entity_type": "domain", "value": "suspicious.example.com"}}
```

A neighbor with high risk score strengthens the case against the original entity. A neighbor with zero risk and high hit count suggests benign infrastructure.

### 3. Pull Event Timeline

Query events to see what the entity has been doing:

```json
{"name": "query_events", "arguments": {"limit": 50}}
```

Look for:
- DNS queries to unusual domains
- Connections to external IPs with high risk scores
- Authentication events from unexpected sources
- Detection findings referencing this entity

### 4. Build Narrative

Synthesize findings into a coherent story:
- What is this entity? (internal host, external server, user account)
- What has it been doing? (normal operations, suspicious connections, lateral movement)
- Who/what is it connected to? (co-occurring entities and their risk)
- What changed? (first_seen vs. last_seen, hit count trends)

### 5. Take Action

Based on the narrative:

**If malicious:**
```json
{
  "name": "submit_verdict",
  "arguments": {
    "finding_id": "<uuid>",
    "verdict": "true_positive",
    "agent_id": "investigator",
    "reasoning": "Entity 10.0.0.42 co-occurs with C2 domain evil.com (23 events) and has risk_score 85. DNS and connection logs confirm beaconing behavior.",
    "confidence": 0.92
  }
}
```

**If benign:**
```json
{
  "name": "submit_verdict",
  "arguments": {
    "finding_id": "<uuid>",
    "verdict": "benign",
    "agent_id": "investigator",
    "reasoning": "Entity is a known monitoring host. All co-occurring entities are internal infrastructure with risk_score 0.",
    "confidence": 0.95
  }
}
```

**If unclear:**
```json
{
  "name": "submit_action",
  "arguments": {
    "action_type": "escalate",
    "agent_id": "investigator",
    "target_entity_type": "ip_address",
    "target_value": "10.0.0.42",
    "reasoning": "Mixed signals: entity has moderate risk_score but co-occurs with both benign and suspicious entities. Human review recommended."
  }
}
```
