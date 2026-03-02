# CLI Overview

`nous-ctl` is the command-line client for querying and interacting with the Nous Core engine.

## Synopsis

```
nous-ctl <COMMAND> [OPTIONS]
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NOUS_ENGINE_ADDR` | `http://127.0.0.1:50051` | gRPC address of the nous-engine |

## Commands

| Command | Description |
|---------|-------------|
| [status](status.md) | Show engine status (event count, findings, uptime) |
| [events](events.md) | Query recent events with optional filters |
| [observe](observe.md) | Generate a context window |
| [entity](entity.md) | Query an entity's risk score |
| [verdict](verdict.md) | Submit a triage verdict for a finding |
| [watch](watch.md) | Stream events in real-time |
| help | Show help message |

## Full Help Output

```
nous-ctl v0.1.0

USAGE:
  nous-ctl <COMMAND> [OPTIONS]

COMMANDS:
  status              Show engine status (event count, findings, uptime)
  events [OPTIONS]    Query recent events
    --class <N>       Filter by OCSF class_uid
    --severity <N>    Filter by minimum severity (0-5)
    --limit <N>       Maximum events to return (default 20)
  observe [OPTIONS]   Generate a context window
    --budget <N>      Token budget (default 4096)
    --format <F>      Output format: structured_json, narrative, delta
  entity <TYPE> <VALUE>  Query entity risk score
  verdict <FINDING_ID> <VERDICT> [OPTIONS]  Submit triage verdict
    --agent <ID>      Agent ID (default: nous-ctl)
    --reasoning <R>   Reasoning text (default: manual)
    --confidence <N>  Confidence 0.0-1.0 (default: 1.0)
  watch [OPTIONS]     Stream events in real-time
    --class <N>       Filter by OCSF class_uid
    --severity <N>    Filter by minimum severity (0-5)
  help                Show this help message

ENVIRONMENT:
  NOUS_ENGINE_ADDR    Engine gRPC address (default: http://127.0.0.1:50051)
```
