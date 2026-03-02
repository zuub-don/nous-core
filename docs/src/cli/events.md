# nous-ctl events

Query recent events from the engine's event buffer.

## Usage

```
nous-ctl events [OPTIONS]
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--class <N>` | `0` (all) | Filter by OCSF class_uid |
| `--severity <N>` | `0` (all) | Filter by minimum severity level (0-5) |
| `--limit <N>` | `20` | Maximum number of events to return |

## Examples

```bash
# Get the 20 most recent events
nous-ctl events

# Only alerts (Detection Finding)
nous-ctl events --class 2004

# High severity and above, limit 50
nous-ctl events --severity 4 --limit 50

# DNS events only
nous-ctl events --class 4003
```

## Output

Events are printed as pretty-printed JSON, one per event:

```
total: 3
{
  "id": "01944abc-...",
  "time": 1705312201000000000,
  "class_uid": 2004,
  "severity": "high",
  "payload": {
    "type": "DetectionFinding",
    "title": "ET MALWARE Known Bad C2 Channel",
    "risk_score": 80,
    ...
  }
}
```

## OCSF Class Reference

| class_uid | Name |
|-----------|------|
| 1001 | Process Activity |
| 2004 | Detection Finding |
| 3001 | Authentication |
| 4001 | Network Connection |
| 4002 | HTTP Activity |
| 4003 | DNS Activity |
| 4014 | TLS Activity |

## Severity Levels

| Value | Name |
|-------|------|
| 0 | Unknown |
| 1 | Info |
| 2 | Low |
| 3 | Medium |
| 4 | High |
| 5 | Critical |
