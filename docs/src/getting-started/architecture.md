# Architecture

Nous Core is organized as a Rust workspace with six crates. This page explains the data flow and key subsystems.

## Crate Map

| Crate | Type | Description |
|-------|------|-------------|
| `nous-core` | lib | Event types, severity, entities, semantic state, context windows |
| `nous-engine` | bin | Headless daemon: ingestion pipeline and event processing |
| `nous-adapters` | lib | Ingestion adapters for Suricata, Zeek, syslog, journald |
| `nous-mcp` | bin | MCP server bridge for AI agent tool-use |
| `nous-ctl` | bin | Control plane client (CLI) |
| `nous-proto` | lib | Protobuf/gRPC service definitions |

## Data Flow Pipeline

```text
Raw Logs → Adapter → NousEvent → Event Bus → Semantic State
                                     │              │
                                     ▼              ▼
                                  gRPC API    Context Windows
                                     │
                             ┌───────┼───────┐
                             ▼       ▼       ▼
                          nous-ctl nous-mcp  gRPC clients
```

### 1. Ingestion

`nous-engine` reads lines from stdin or a file. Each line is dispatched to the configured adapter (Suricata, Zeek, syslog, or journald). The adapter parses the raw format and returns a typed `NousEvent`.

### 2. Event Bus

Successfully parsed events are broadcast on a `tokio::sync::broadcast` channel. This allows multiple subscribers (the gRPC streaming endpoint, the event buffer, the state engine) to receive events concurrently.

### 3. Semantic State

The `SemanticState` struct is the rolling in-memory model. On each event it updates:

- **Event counters** — total count and per-OCSF-class counts
- **Severity histogram** — distribution across 6 severity levels
- **Entity metadata** — auto-extracted entities with risk scores, first/last seen, hit counts
- **Active findings** — detection findings awaiting triage

### 4. Context Window Generation

The `ContextGenerator` compresses semantic state into token-budgeted reports. It supports three output formats:

- **structured_json** — machine-readable sections for tool-use agents
- **narrative** — natural language for chat-based agents
- **delta** — changes since last observation

Token budgets range from 1,024 to 16,384 tokens (~4 chars per token).

### 5. API Layer

Two API surfaces expose the state to consumers:

- **gRPC** (via `nous-proto`) — 7 RPCs including streaming
- **MCP** (via `nous-mcp`) — JSON-RPC 2.0 over stdio, 6 tools

### 6. Feedback Loop

AI agents close the loop by submitting:

- **Verdicts** — triage decisions on findings (true_positive, false_positive, benign, needs_investigation)
- **Actions** — response actions on entities (escalate, suppress, isolate, block, allowlist)

These feed back into the semantic state, adjusting entity risk scores and finding statuses.

## Key Design Decisions

- **OCSF alignment** — all events use OCSF class UIDs and category UIDs for interoperability
- **Token budgeting** — context windows are sized to fit LLM context limits
- **Adapter pattern** — each log source implements the `Adapter` trait with a single `parse_line()` method
- **In-memory state** — no persistent storage required (optional PostgreSQL via feature flag)
- **Headless daemon** — `nous-engine` has no UI; all interaction is through gRPC/MCP/CLI
