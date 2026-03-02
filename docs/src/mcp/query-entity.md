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
| `hit_count` | integer | Total events referencing this entity |
| `first_seen` | integer | First seen timestamp (epoch nanos) |
| `last_seen` | integer | Last seen timestamp (epoch nanos) |
| `co_occurrences` | array | Co-occurring entities sorted by count (see below) |

### Co-occurrence Object

| Field | Type | Description |
|-------|------|-------------|
| `entity_type` | string | Entity type of the neighbor |
| `value` | string | Value of the neighbor |
| `count` | integer | Number of shared events |

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
  "risk_score": 85,
  "hit_count": 47,
  "first_seen": 1709337600000000000,
  "last_seen": 1709341200000000000,
  "co_occurrences": [
    {"entity_type": "domain", "value": "evil.com", "count": 23},
    {"entity_type": "ip_address", "value": "10.0.0.2", "count": 15}
  ]
}
```

## Example: Entity Not Found

```json
{
  "found": false,
  "entity_type": "domain",
  "value": "unknown.example.com",
  "risk_score": 0,
  "hit_count": 0,
  "first_seen": 0,
  "last_seen": 0,
  "co_occurrences": []
}
```
