# Nous Core

**AI-native security observation and action layer.**

Nous Core is the missing middle layer between existing security telemetry (Suricata, Zeek, syslog, journald) and AI agents. It ingests, normalizes to an OCSF-aligned schema, compresses into token-budgeted context windows, and exposes a typed MCP + gRPC action API.

## What Nous Core Is NOT

- **Not a SIEM** — no log storage, no dashboards, no query language
- **Not a detection engine** — no rules, no signatures, no correlation
- **Not a SOAR** — no playbooks, no case management

## Architecture

```text
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  Suricata    │   │    Zeek      │   │   syslog     │
│  EVE JSON    │   │    logs      │   │  journald    │
└──────┬───────┘   └──────┬───────┘   └──────┬───────┘
       │                  │                  │
       └──────────────────┼──────────────────┘
                          │
                   ┌──────▼───────┐
                   │  nous-engine │  Ingestion + Normalization
                   │  (headless)  │  OCSF-aligned NousEvent
                   └──────┬───────┘
                          │
              ┌───────────┼───────────┐
              │           │           │
       ┌──────▼──┐  ┌─────▼────┐  ┌──▼──────┐
       │Semantic │  │ Context  │  │  Action  │
       │ State   │  │ Windows  │  │   API    │
       └─────────┘  └──────────┘  └──┬──────┘
                                     │
                          ┌──────────┼──────────┐
                          │          │          │
                     ┌────▼───┐ ┌───▼────┐ ┌───▼────┐
                     │  MCP   │ │  gRPC  │ │nous-ctl│
                     │ Server │ │  API   │ │  TUI   │
                     └────────┘ └────────┘ └────────┘
```

## Crates

| Crate | Type | Description |
| --- | --- | --- |
| `nous-core` | lib | Event types, severity, entities, semantic state, context windows |
| `nous-engine` | bin | Headless daemon: ingestion pipeline and event processing |
| `nous-adapters` | lib | Ingestion adapters for Suricata, Zeek, syslog, journald |
| `nous-mcp` | bin | MCP server bridge for AI agent tool-use |
| `nous-ctl` | bin | Control plane client (TUI/CLI) |
| `nous-proto` | lib | Protobuf/gRPC service definitions |

## Quick Start

```bash
# Build
cargo build --workspace

# Test
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# All checks (requires just: cargo install just)
just check
```

## Design Documents

RFCs live in the sibling `hacktui-rd/rfcs/` directory:

- **RFC-001**: Vision, Scope, Architecture
- **RFC-002**: Event Schema and OCSF Alignment
- **RFC-003**: Context Windowing and Semantic Compression (planned)
- **RFC-004**: Agent Action API — MCP + gRPC (planned)
- **RFC-005**: Ingestion Adapters (planned)
- **RFC-006**: Feedback Loops (planned)

## License

Apache-2.0. See [LICENSE](LICENSE).
