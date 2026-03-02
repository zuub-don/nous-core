# nous-ctl status

Show the current engine status.

## Usage

```
nous-ctl status
```

## Arguments

None.

## Output

```
nous-engine v0.1.0
  events ingested:  1247
  active findings:  3
  uptime:           42s
```

## Fields

| Field | Description |
|-------|-------------|
| `events ingested` | Total number of events processed since engine startup |
| `active findings` | Number of detection findings awaiting triage |
| `uptime` | Seconds since the engine started |

## Errors

If the engine is unreachable:

```
Error: failed to connect to engine at http://127.0.0.1:50051
```
