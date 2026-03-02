# nous-ctl watch

Stream events from the engine in real-time. Events are printed as pretty-printed JSON as they arrive. Press `Ctrl+C` to stop.

## Usage

```
nous-ctl watch [OPTIONS]
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--class <N>` | `0` (all) | Filter by OCSF class_uid |
| `--severity <N>` | `0` (all) | Filter by minimum severity level (0-5) |

## Examples

```bash
# Stream all events
nous-ctl watch

# Stream only alerts
nous-ctl watch --class 2004

# Stream high severity and above
nous-ctl watch --severity 4

# Stream DNS events
nous-ctl watch --class 4003
```

## Output

Events stream continuously, one JSON object per event:

```json
{
  "id": "01944abc-...",
  "time": 1705312201000000000,
  "class_uid": 4003,
  "severity": "info",
  "payload": {
    "type": "DnsActivity",
    "activity_id": 1,
    "query": {
      "hostname": "example.com",
      "type_id": 1,
      "class": 1
    },
    ...
  }
}
```

## Notes

- The stream uses gRPC server-side streaming (`StreamEvents` RPC)
- If the connection drops, the command exits with a stream error
- Filtering happens server-side, so only matching events are transmitted
