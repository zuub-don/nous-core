# Threat Hunt from IOC

Starting from a known indicator of compromise (IOC), map the blast radius and take containment actions.

## When to Use

- A new IOC is received (IP, domain, hash) from threat intel
- An entity's risk score spikes and you need to understand impact

## Workflow

### 1. Query the IOC Entity

Look up the indicator to see its current state and relationships:

```json
{"name": "query_entity", "arguments": {"entity_type": "ip_address", "value": "203.0.113.50"}}
```

Examine:
- `risk_score` — how risky is this entity already?
- `hit_count` — how active is it in the environment?
- `co_occurrences` — what other entities are connected?

### 2. Pivot Through Co-occurrences

For each co-occurring entity, query it in turn:

```json
{"name": "query_entity", "arguments": {"entity_type": "domain", "value": "evil.com"}}
```

Build a graph of related entities. High co-occurrence counts indicate strong relationships.

### 3. Pull Event Timeline

Query events involving the IOC and its neighbors:

```json
{"name": "query_events", "arguments": {"limit": 50}}
```

Filter through the results to reconstruct the timeline of activity.

### 4. Assess Scope

Based on the entity graph and event timeline, determine:
- How many internal hosts communicated with the IOC?
- Are there lateral movement indicators (co-occurring internal IPs)?
- Is there data exfiltration evidence (unusual domains)?

### 5. Take Action

Submit containment actions for confirmed threats:

```json
{
  "name": "submit_action",
  "arguments": {
    "action_type": "block",
    "agent_id": "hunt-agent",
    "target_entity_type": "ip_address",
    "target_value": "203.0.113.50",
    "reasoning": "Confirmed C2 server. Co-occurs with 3 internal hosts and malicious domain evil.com."
  }
}
```

For internal hosts that need investigation:

```json
{
  "name": "submit_action",
  "arguments": {
    "action_type": "isolate",
    "agent_id": "hunt-agent",
    "target_entity_type": "ip_address",
    "target_value": "10.0.0.42",
    "reasoning": "Internal host with 15 connections to confirmed C2 203.0.113.50."
  }
}
```

## Action Guide

| Action | When |
|--------|------|
| `block` | Block external IOCs at perimeter |
| `isolate` | Quarantine compromised internal hosts |
| `escalate` | Escalate to human analyst when scope is large |
