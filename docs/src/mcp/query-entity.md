# query_entity

Look up an entity's risk score by type and value.

## Parameters

All parameters are required.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `entity_type` | string | Yes | Entity type (see enum below) |
| `value` | string | Yes | Entity value (e.g., IP address, domain name) |

### entity_type Enum

| Value | Description |
|-------|-------------|
| `ip_address` | IPv4 or IPv6 address |
| `domain` | Domain name |
| `hostname` | Host name |
| `user` | Username |
| `process` | Process name |
| `file` | File path |
| `url` | URL |

## Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `found` | boolean | Whether the entity is tracked |
| `entity_type` | string | Entity type (echoed back) |
| `value` | string | Entity value (echoed back) |
| `risk_score` | integer | Risk score (0-100), 0 if not found |

## Example: Entity Found

Request:

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "query_entity",
    "arguments": {
      "entity_type": "ip_address",
      "value": "10.0.0.99"
    }
  }
}
```

Parsed tool result:

```json
{
  "found": true,
  "entity_type": "ip_address",
  "value": "10.0.0.99",
  "risk_score": 85
}
```

## Example: Entity Not Found

```json
{
  "found": false,
  "entity_type": "domain",
  "value": "unknown.example.com",
  "risk_score": 0
}
```
