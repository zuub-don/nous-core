# MCP Tool Overview

`nous-mcp` exposes Nous Core functionality to AI agents via the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP). It communicates over JSON-RPC 2.0 on stdio and proxies tool calls to `nous-engine` via gRPC.

## Protocol

- **Transport**: stdio (stdin/stdout)
- **Protocol**: JSON-RPC 2.0
- **MCP version**: 2024-11-05

## Configuration

Set the engine address via environment variable:

```bash
NOUS_ENGINE_ADDR=http://127.0.0.1:50051 nous-mcp
```

## Claude Desktop Integration

```json
{
  "mcpServers": {
    "nous": {
      "command": "nous-mcp",
      "env": {
        "NOUS_ENGINE_ADDR": "http://127.0.0.1:50051"
      }
    }
  }
}
```

## Available Tools

| Tool | Parameters | Description |
|------|-----------|-------------|
| [get_status](get-status.md) | *(none)* | Get engine status: event count, findings, uptime |
| [query_events](query-events.md) | class_uid?, min_severity?, limit? | Query recent events with filters |
| [observe](observe.md) | token_budget?, format? | Generate a context window |
| [query_entity](query-entity.md) | entity_type, value | Look up entity risk score |
| [submit_verdict](submit-verdict.md) | finding_id, verdict, agent_id, reasoning, confidence | Submit triage verdict |
| [submit_action](submit-action.md) | action_type, agent_id, target_entity_type, target_value, reasoning | Submit response action |

## JSON-RPC Example

Request:

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get_status", "arguments": {}}}
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\n  \"event_count\": 1247,\n  \"active_findings\": 3,\n  \"uptime_seconds\": 42,\n  \"version\": \"0.1.0\"\n}"
      }
    ]
  }
}
```
