# Environment Variables

All environment variables used by Nous Core binaries.

## Variable Reference

| Variable | Used By | Default | Description |
|----------|---------|---------|-------------|
| `NOUS_ENGINE_ADDR` | nous-ctl, nous-mcp | `http://127.0.0.1:50051` | gRPC address of the nous-engine instance |
| `RUST_LOG` | all binaries | `nous=info` | Logging level filter (tracing/env_filter syntax) |

## NOUS_ENGINE_ADDR

Controls which `nous-engine` instance the client tools connect to.

```bash
# Local default
export NOUS_ENGINE_ADDR=http://127.0.0.1:50051

# Remote engine
export NOUS_ENGINE_ADDR=http://192.168.1.10:50051

# Non-standard port
export NOUS_ENGINE_ADDR=http://127.0.0.1:9090
```

## RUST_LOG

Controls log output via the `tracing-subscriber` EnvFilter. Logs go to stderr for all binaries.

```bash
# Info level (default)
RUST_LOG=info nous-engine --input -

# Debug for a specific crate
RUST_LOG=nous_engine=debug nous-engine --input -

# Trace everything
RUST_LOG=trace nous-engine --input -

# Combine filters
RUST_LOG=nous_engine=debug,nous_adapters=trace nous-engine --input -
```

`nous-mcp` always logs to stderr so that stdout remains clean for JSON-RPC communication.
