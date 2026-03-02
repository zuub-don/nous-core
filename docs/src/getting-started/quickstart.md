# Quickstart

This walkthrough runs a complete Suricata end-to-end pipeline in 7 steps: start the engine, query status, view events, generate a context window, look up an entity, stream live events, and connect an AI agent via MCP.

## Step 1: Start the Engine with Suricata Input

```bash
# Tail Suricata EVE JSON into nous-engine
tail -f /var/log/suricata/eve.json | \
  nous-engine --adapter suricata --grpc-port 50051
```

Or from a static file:

```bash
nous-engine --input /var/log/suricata/eve.json --adapter suricata
```

The engine starts ingesting events and serving the gRPC API on port 50051.

## Step 2: Check Engine Status

```bash
nous-ctl status
```

Output:

```
nous-engine v0.1.0
  events ingested:  1247
  active findings:  3
  uptime:           42s
```

## Step 3: Query Recent Events

```bash
# All events (default limit 20)
nous-ctl events

# Only alerts (class 2004), severity High or above
nous-ctl events --class 2004 --severity 4
```

## Step 4: Generate a Context Window

```bash
# Default: structured_json, 4096 tokens
nous-ctl observe

# Narrative format, larger budget
nous-ctl observe --format narrative --budget 8192
```

The context window is a compressed situation report designed for LLM consumption.

## Step 5: Look Up an Entity

```bash
nous-ctl entity ip_address 10.0.0.1
```

Output:

```
entity:     ip_address = 10.0.0.1
risk_score: 75
```

## Step 6: Stream Live Events

```bash
# Stream all events
nous-ctl watch

# Stream only alerts
nous-ctl watch --class 2004

# Press Ctrl+C to stop
```

## Step 7: Connect an AI Agent via MCP

Start the MCP server (it communicates over stdin/stdout):

```bash
NOUS_ENGINE_ADDR=http://127.0.0.1:50051 nous-mcp
```

Configure Claude Desktop to use it:

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

The AI agent now has access to 6 tools: `get_status`, `query_events`, `observe`, `query_entity`, `submit_verdict`, and `submit_action`.

## Next Steps

- [Architecture](architecture.md) — understand the data flow in detail
- [Adapters](../adapters/overview.md) — configure other log sources
- [CLI Reference](../cli/overview.md) — full command documentation
- [MCP Tools](../mcp/overview.md) — AI agent integration guide
