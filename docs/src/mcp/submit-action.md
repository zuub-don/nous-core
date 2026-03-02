# submit_action

Submit a response action for a security entity. This is how AI agents take action on threats.

## Parameters

All parameters are required.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `action_type` | string | Yes | Type of action (see enum below) |
| `agent_id` | string | Yes | ID of the agent submitting the action |
| `target_entity_type` | string | Yes | Entity type of the target |
| `target_value` | string | Yes | Value of the target entity |
| `reasoning` | string | Yes | Explanation for the action |

### action_type Enum

| Value | Description |
|-------|-------------|
| `escalate` | Escalate to a human analyst |
| `suppress` | Suppress future alerts for this pattern |
| `isolate` | Isolate the target entity from the network |
| `block` | Block the target entity |
| `allowlist` | Add the target entity to an allowlist |

### target_entity_type Values

Any entity type: `ip_address`, `domain`, `hostname`, `user`, `process`, `file`, `url`.

## Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `action_id` | string | UUID of the created action |
| `accepted` | boolean | Whether the action was accepted |

## Example

Request:

```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "tools/call",
  "params": {
    "name": "submit_action",
    "arguments": {
      "action_type": "block",
      "agent_id": "claude-security-agent",
      "target_entity_type": "ip_address",
      "target_value": "10.0.0.99",
      "reasoning": "Confirmed C2 beacon. Multiple high-severity alerts from this IP."
    }
  }
}
```

Parsed tool result:

```json
{
  "action_id": "01944ghi-0000-7000-8000-000000000003",
  "accepted": true
}
```
