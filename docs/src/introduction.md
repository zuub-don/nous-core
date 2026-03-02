# Introduction

**Nous Core** is the AI-native security observation and action layer. It sits between existing security telemetry (Suricata, Zeek, syslog, journald) and AI agents, providing:

- **Ingestion & Normalization** — four adapters that parse raw log formats into an OCSF-aligned event schema
- **Semantic State** — a rolling in-memory model of "what's happening right now" with entity risk tracking
- **Context Windows** — token-budgeted situation reports compressed for LLM consumption
- **Action API** — typed gRPC and MCP interfaces for AI agents to query, triage, and act

## What Nous Core Is NOT

- **Not a SIEM** — no log storage, no dashboards, no query language
- **Not a detection engine** — no rules, no signatures, no correlation
- **Not a SOAR** — no playbooks, no case management

Nous Core is the **missing middle layer** that makes security telemetry consumable by AI agents in real-time.

## The Three Binaries

| Binary | Purpose |
|--------|---------|
| `nous-engine` | Headless daemon — ingests events, maintains state, serves gRPC API |
| `nous-mcp` | MCP server — bridges the gRPC API to AI agents via JSON-RPC 2.0 over stdio |
| `nous-ctl` | CLI client — query status, events, entities, submit verdicts, stream events |

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
                     │ Server │ │  API   │ │  CLI   │
                     └────────┘ └────────┘ └────────┘
```

## Data Flow

1. **Ingest** — `nous-engine` reads lines from a file or stdin, dispatches to the configured adapter
2. **Normalize** — the adapter parses the raw format and produces a `NousEvent` with OCSF class, severity, and typed payload
3. **State Update** — the semantic state engine ingests each event, updating counters, entity metadata, and severity histograms
4. **Broadcast** — events are broadcast on an internal channel for real-time subscribers
5. **Query** — clients (`nous-ctl`, `nous-mcp`, or direct gRPC) query the state and event buffer
6. **Observe** — context window generation compresses state into token-budgeted reports for AI agents
7. **Act** — agents submit verdicts and actions that feed back into the state model
