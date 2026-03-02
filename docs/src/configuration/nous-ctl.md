# nous-ctl Configuration

`nous-ctl` is the CLI client for querying and interacting with the Nous Core engine.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NOUS_ENGINE_ADDR` | `http://127.0.0.1:50051` | gRPC address of the nous-engine instance |

## Connecting to a Remote Engine

By default, `nous-ctl` connects to `localhost:50051`. To connect to a remote engine:

```bash
# Set for the current session
export NOUS_ENGINE_ADDR=http://192.168.1.10:50051

# Or per-command
NOUS_ENGINE_ADDR=http://192.168.1.10:50051 nous-ctl status
```

## Verifying Connectivity

```bash
nous-ctl status
```

If the engine is unreachable, you'll see:

```
Error: failed to connect to engine at http://127.0.0.1:50051
```

Check that `nous-engine` is running and the address/port match.

## Command Reference

See the full [CLI Reference](../cli/overview.md) for all commands and options.
