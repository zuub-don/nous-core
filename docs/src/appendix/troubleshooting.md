# Troubleshooting

Common issues and how to resolve them.

## Connection Failed

**Symptom:**

```
Error: failed to connect to engine at http://127.0.0.1:50051
```

**Causes:**

- `nous-engine` is not running
- The engine is running on a different port
- `NOUS_ENGINE_ADDR` is set incorrectly

**Fix:**

1. Verify the engine is running: check for the `nous-engine` process
2. Check the port: `--grpc-port` defaults to 50051
3. Set the correct address: `export NOUS_ENGINE_ADDR=http://HOST:PORT`

## No Events Appearing

**Symptom:** `nous-ctl events` returns `total: 0` despite feeding data into the engine.

**Causes:**

- Input format doesn't match the selected adapter
- The adapter is rejecting all lines (parse errors)
- The input source is empty or not producing data

**Fix:**

1. Check the adapter matches your input: `--adapter suricata` for EVE JSON, `--adapter zeek` for Zeek logs
2. Run with debug logging to see parse errors: `RUST_LOG=debug nous-engine --input ...`
3. Verify the input source is producing data: `tail /var/log/suricata/eve.json`

## MCP Server Not Responding

**Symptom:** Claude Desktop or another MCP client can't communicate with `nous-mcp`.

**Causes:**

- The `nous-mcp` binary is not found
- The command path in the MCP config is wrong
- The engine is not running (tool calls fail on first use)

**Fix:**

1. Verify the binary exists and is executable
2. Use the full path in `mcp_servers` config if not in PATH
3. Start `nous-engine` before making tool calls
4. Check stderr output from `nous-mcp` for error messages

## Persistence Build Errors

**Symptom:** Build fails when using `--features persistence`.

**Causes:**

- `sqlx` dependencies missing (libpq)
- Incorrect Rust version (need 1.80+)

**Fix:**

1. Install PostgreSQL development libraries:
   - Debian/Ubuntu: `apt install libpq-dev`
   - Fedora/RHEL: `dnf install postgresql-devel`
   - macOS: `brew install libpq`
2. Ensure Rust 1.80+: `rustup update`

## Zeek Adapter: "no #fields header parsed yet"

**Symptom:** The Zeek adapter errors with "no #fields header parsed yet".

**Cause:** Data lines arrived before the `#fields` header directive.

**Fix:** Ensure the Zeek log file includes its header directives. If piping multiple files, include headers from each file:

```bash
cat /var/log/zeek/current/conn.log | nous-engine --adapter zeek
```

## Syslog Adapter: "syslog line too short"

**Symptom:** The syslog adapter rejects lines.

**Cause:** The line doesn't match the expected BSD syslog format: `<PRI>Mon DD HH:MM:SS hostname app: message`.

**Fix:** Verify your syslog output format. The adapter expects at least 5 space-separated tokens after the priority prefix.

## High Memory Usage

**Symptom:** `nous-engine` uses excessive memory.

**Cause:** Large `--buffer-size` or high event throughput.

**Fix:**

1. Reduce buffer size: `--buffer-size 500`
2. Use severity filtering in event queries to limit returned data
3. Use the `observe` tool instead of `query_events` for AI agent consumption — context windows are designed to be compact
