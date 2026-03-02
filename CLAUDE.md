# Nous Core

AI-native security observation layer. Rust workspace, 6 crates.

## Quick Commands

```bash
cargo build --workspace                  # Build everything
cargo test --workspace                   # Run all tests
cargo clippy --workspace -- -D warnings  # Lint (must pass, zero warnings)
cargo fmt --check                        # Format check
just check                               # All of the above in sequence
```

## Architecture

```
crates/
  nous-core/       # Core lib: event types, severity, entity, semantic state, context windows
  nous-engine/     # Binary: headless daemon (ingestion → state → API)
  nous-adapters/   # Lib: ingestion adapters (Suricata EVE, Zeek, syslog, journald)
  nous-mcp/        # Binary: MCP server (bridges core API to AI agents)
  nous-ctl/        # Binary: control plane client (TUI/CLI)
  nous-proto/      # Lib: protobuf/gRPC service definitions
```

## Code Style

- Edition 2021, MSRV 1.80
- Use `thiserror` for library errors, `anyhow` for binary errors
- No `.unwrap()` in library code; `.expect()` only for proven invariants
- Prefer `&str` / `Cow<'_, str>` over `String` in hot paths
- All public items must have doc comments
- snake_case functions, PascalCase types, SCREAMING_SNAKE_CASE constants
- Imports: std first, external crates second, local modules third
- No wildcard imports except `use super::*` in test modules

## Event Schema

Events follow OCSF alignment. Core types live in `nous-core/src/event.rs`.
Every event wraps in `NousEvent` envelope with UUIDv7, nanosecond timestamps, OCSF class_uid, severity, source attribution, and typed payload.

## Testing

- Every module has `#[cfg(test)] mod tests` with unit tests
- Run single crate: `cargo test -p nous-core`
- Tests follow Arrange-Act-Assert pattern
- Always test: success path, error path, edge cases, serde roundtrip

## Key Dependencies

| Purpose | Crate | Notes |
|---|---|---|
| Async | tokio | Full features |
| Serialization | sonic-rs + serde_json | sonic-rs for hot path |
| SQL | sqlx (Postgres) | Async-native |
| Logging | tracing | Structured spans |
| gRPC | tonic + prost | Code-gen from protobuf |
| Errors | thiserror (lib) / anyhow (bin) | |

## RFCs

Design documents are in the sibling project `../hacktui-rd/rfcs/`. Read them for architectural context before making significant changes.
