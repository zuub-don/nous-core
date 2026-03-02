# submit_verdict

Submit a triage verdict for a security finding. This is how AI agents classify and disposition detection findings.

## Parameters

All parameters are required.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `finding_id` | string | Yes | UUID of the finding to verdict |
| `verdict` | string | Yes | Triage verdict (see enum below) |
| `agent_id` | string | Yes | ID of the agent submitting the verdict |
| `reasoning` | string | Yes | Explanation for the verdict |
| `confidence` | number | Yes | Confidence score (0.0 to 1.0) |

### verdict Enum

| Value | Description | Effect |
|-------|-------------|--------|
| `true_positive` | Confirmed malicious | Escalate; increase entity risk scores |
| `false_positive` | Not malicious | Suppress future occurrences; decrease risk |
| `benign` | Legitimate activity | No action needed; slight risk decrease |
| `needs_investigation` | Insufficient information | Keep finding active; no risk change |

## Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `verdict_id` | string | UUID of the created verdict |
| `accepted` | boolean | Whether the verdict was accepted |

## Example

Request:

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "submit_verdict",
    "arguments": {
      "finding_id": "01944abc-def0-7000-8000-000000000001",
      "verdict": "true_positive",
      "agent_id": "claude-security-agent",
      "reasoning": "Matched known C2 beacon pattern. Source IP has high risk score and multiple alert hits.",
      "confidence": 0.95
    }
  }
}
```

Parsed tool result:

```json
{
  "verdict_id": "01944def-0000-7000-8000-000000000002",
  "accepted": true
}
```
