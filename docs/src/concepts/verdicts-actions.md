# Verdicts & Actions

Verdicts and actions are the feedback mechanisms that allow AI agents to close the loop — classifying findings and taking response actions that feed back into the semantic state.

## Verdicts

A verdict is a triage decision on a detection finding. It classifies the finding and adjusts the system's understanding of the threat.

### Verdict Types

| Verdict | Description | Effect on State |
|---------|-------------|-----------------|
| `true_positive` | Confirmed malicious | Escalate finding; increase entity risk scores |
| `false_positive` | Not actually malicious | Suppress future alerts from this rule; decrease entity risk |
| `benign` | Legitimate activity | Mark as resolved; slight risk decrease |
| `needs_investigation` | Insufficient information | Keep finding active; no risk change |

### Verdict Structure

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID (v7) | Unique verdict identifier |
| `finding_id` | UUID | The finding this verdict applies to |
| `verdict` | TriageVerdict | Classification (see table above) |
| `agent_id` | String | ID of the agent that submitted the verdict |
| `reasoning` | String | Explanation for the decision |
| `confidence` | f64 | Confidence score (0.0 to 1.0) |
| `created_at` | i64 | Timestamp (nanoseconds since epoch) |

## Actions

An action is a response directive submitted by an agent. Actions target specific entities and express an intent (e.g., block, isolate).

### Action Types

| Action | Description |
|--------|-------------|
| `escalate` | Escalate to a human analyst for review |
| `suppress` | Suppress future alerts matching this pattern |
| `isolate` | Isolate the target entity from the network |
| `block` | Block the target entity (e.g., firewall rule) |
| `allowlist` | Add the target entity to an allowlist |

### Action Structure

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID (v7) | Unique action identifier |
| `action_type` | ActionType | Type of action (see table above) |
| `agent_id` | String | ID of the agent that submitted the action |
| `target_entity_type` | String | Entity type of the target |
| `target_value` | String | Value of the target entity |
| `reasoning` | String | Explanation for the action |
| `created_at` | i64 | Timestamp (nanoseconds since epoch) |

## The Feedback Loop

```text
Events → State → Context Window → AI Agent
                                      │
                                      ├─ Verdict → State (risk adjustment, finding resolution)
                                      │
                                      └─ Action → State (entity risk, suppression rules)
```

1. Events flow in and update the semantic state
2. The AI agent observes the state via a context window
3. The agent submits verdicts on findings and/or actions on entities
4. Verdicts and actions feed back into the state:
   - `true_positive` verdicts increase risk scores of associated entities
   - `false_positive` verdicts add suppression rules and decrease risk
   - `block`/`isolate` actions increase entity risk visibility
   - `allowlist` actions decrease entity risk
5. The next observation reflects these changes

This loop enables AI agents to progressively refine the security posture through iterative triage and response.
