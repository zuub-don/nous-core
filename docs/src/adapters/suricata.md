# Suricata Adapter

The Suricata adapter parses [EVE JSON](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html) output — the NDJSON (newline-delimited JSON) format Suricata writes to `eve.json`.

## Input Format

Each line is a self-contained JSON object with an `event_type` field:

```json
{
  "timestamp": "2024-01-15T10:30:00.000000+0000",
  "event_type": "alert",
  "src_ip": "10.0.0.1",
  "src_port": 54321,
  "dest_ip": "192.168.1.1",
  "dest_port": 80,
  "proto": "TCP",
  "alert": { ... }
}
```

## Event Type Mapping

| Suricata `event_type` | OCSF class_uid | NousEvent Payload |
|----------------------|----------------|-------------------|
| `alert` | 2004 | `DetectionFinding` |
| `dns` | 4003 | `DnsActivity` |
| `flow` | 4001 | `NetworkConnection` |
| `http` | 4002 | `HttpActivity` |
| `tls` | 4014 | `TlsActivity` |
| *(anything else)* | 0 | `Generic` |

## Severity Mapping

Suricata alert priority maps to Nous Core severity:

| Suricata Priority | Severity | Risk Score |
|-------------------|----------|------------|
| 1 | High (4) | 80 |
| 2 | Medium (3) | 60 |
| 3 | Low (2) | 40 |
| 4+ | Info (1) | 20 |

Non-alert events (dns, flow, http, tls) default to `Info` severity.

## Timestamp Parsing

The adapter handles both RFC 3339 and Suricata's slightly non-standard format:

- `2024-01-15T10:30:00.000000+00:00` (RFC 3339)
- `2024-01-15T10:30:00.000000+0000` (Suricata native)

## Alert Example

Input:

```json
{
  "timestamp": "2024-01-15T10:30:00.000000+0000",
  "event_type": "alert",
  "src_ip": "10.0.0.1",
  "src_port": 54321,
  "dest_ip": "192.168.1.1",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "signature_id": 2024001,
    "signature": "ET MALWARE Known Bad C2 Channel",
    "category": "A Network Trojan was detected",
    "severity": 1
  }
}
```

Produces a `DetectionFinding` with:
- `title`: "ET MALWARE Known Bad C2 Channel"
- `risk_level`: High
- `risk_score`: 80
- `rule.uid`: "2024001"

## DNS Example

Input:

```json
{
  "timestamp": "2024-01-15T10:30:01.000000+0000",
  "event_type": "dns",
  "src_ip": "10.0.0.5",
  "src_port": 44123,
  "dest_ip": "8.8.8.8",
  "dest_port": 53,
  "dns": {
    "type": "query",
    "rrname": "example.com",
    "rrtype": "A",
    "id": 12345
  }
}
```

Produces a `DnsActivity` with `activity_id: 1` (query). DNS answers (`"type": "answer"`) produce `activity_id: 2` with response data.

## Usage

```bash
tail -f /var/log/suricata/eve.json | nous-engine --adapter suricata
```
