# nous-engine Configuration

`nous-engine` is the headless ingestion daemon. It reads security telemetry, normalizes it to OCSF events, maintains semantic state, and serves the gRPC API.

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--input <path\|->` | `-` (stdin) | Event source: file path or `-` for stdin |
| `--grpc-port <port>` | `50051` | gRPC API listen port |
| `--buffer-size <n>` | `1000` | Maximum number of recent events to buffer in memory |
| `--adapter <name>` | `auto` | Adapter to use: `suricata`, `zeek`, `syslog`, `journald`, or `auto` |
| `--db-url <url>` | *(none)* | PostgreSQL connection URL (requires `persistence` feature) |

## Adapter Selection

When `--adapter auto` is set (the default), the engine attempts to detect the input format automatically. For reliable operation, specify the adapter explicitly:

```bash
# Suricata EVE JSON
nous-engine --input /var/log/suricata/eve.json --adapter suricata

# Zeek logs
nous-engine --input /var/log/zeek/current/conn.log --adapter zeek

# Syslog
nous-engine --input /var/log/syslog --adapter syslog

# Journald
journalctl -f -o json | nous-engine --adapter journald
```

## Logging

`nous-engine` uses the `tracing` crate with the `RUST_LOG` environment variable:

```bash
# Default info-level logging
RUST_LOG=info nous-engine --input /var/log/suricata/eve.json

# Debug logging for the engine
RUST_LOG=nous_engine=debug nous-engine --input -

# Trace all crates
RUST_LOG=trace nous-engine --input -
```

## Examples

### Suricata with Custom Port

```bash
tail -f /var/log/suricata/eve.json | \
  nous-engine --adapter suricata --grpc-port 9090 --buffer-size 5000
```

### Zeek with Persistence

```bash
nous-engine \
  --input /var/log/zeek/current/conn.log \
  --adapter zeek \
  --db-url postgres://localhost/nous
```

### Multiple Sources via Process Substitution

```bash
cat <(tail -f /var/log/suricata/eve.json) | \
  nous-engine --adapter suricata
```

For ingesting multiple sources simultaneously, run separate engine instances on different gRPC ports or combine logs upstream.
