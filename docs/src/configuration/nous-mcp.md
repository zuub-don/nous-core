# nous-mcp Configuration

`nous-mcp` is the MCP (Model Context Protocol) server that bridges the Nous Core gRPC API to AI agents. It communicates over JSON-RPC 2.0 on stdio.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NOUS_ENGINE_ADDR` | `http://127.0.0.1:50051` | gRPC address of the nous-engine instance |
| `RUST_LOG` | `nous=info` | Logging level (logs go to stderr) |

## Transport

`nous-mcp` uses **stdio transport**: it reads JSON-RPC requests from stdin and writes responses to stdout. Logs are written to stderr so they don't interfere with the protocol.

The server lazily connects to `nous-engine` on the first tool call, so the engine does not need to be running when `nous-mcp` starts.

## Claude Desktop Configuration

Add `nous-mcp` to your Claude Desktop `mcp_servers` configuration:

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

If the binary is not in your PATH, use the full path:

```json
{
  "mcpServers": {
    "nous": {
      "command": "/path/to/target/release/nous-mcp",
      "env": {
        "NOUS_ENGINE_ADDR": "http://127.0.0.1:50051"
      }
    }
  }
}
```

## Protocol Details

`nous-mcp` implements the MCP protocol version `2024-11-05` and supports:

- `initialize` — returns server info and capabilities
- `tools/list` — returns the 6 available tool definitions
- `tools/call` — executes a tool by proxying to the engine via gRPC

See the [MCP Tool Reference](../mcp/overview.md) for the full tool catalog.
