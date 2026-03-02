# Zeek Adapter

The Zeek adapter parses Zeek's tab-separated log files. It tracks `#path` and `#fields` header directives to determine the log type and column layout.

## Input Format

Zeek logs use tab-separated values with header directives:

```
#separator \x09
#path	conn
#fields	ts	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	orig_bytes	resp_bytes	duration
1705312201.123456	10.0.0.1	54321	93.184.216.34	443	tcp	1500	32000	1.5
```

### Header Directives

- `#path` — specifies the log type (e.g., `conn`, `dns`, `http`, `ssl`, `notice`)
- `#fields` — specifies the column names in tab-separated order
- Other `#` lines (e.g., `#separator`, `#open`, `#close`) are ignored

The `#fields` header **must** be parsed before any data lines. If a data line arrives without a prior `#fields` header, the adapter returns an error.

### Unset Fields

Zeek uses `-` to represent unset or missing values. The adapter treats `-` as `None` for optional fields.

## Log Type Mapping

| Zeek Log (`#path`) | OCSF class_uid | NousEvent Payload |
|--------------------|----------------|-------------------|
| `conn` | 4001 | `NetworkConnection` |
| `dns` | 4003 | `DnsActivity` |
| `http` | 4002 | `HttpActivity` |
| `ssl` | 4014 | `TlsActivity` |
| `notice` | 2004 | `DetectionFinding` |
| *(anything else)* | 0 | `Generic` |

## Timestamp Format

Zeek timestamps are epoch seconds with microsecond decimal precision:

```
1705312201.123456
```

The adapter converts these to nanoseconds. A `-` timestamp is treated as 0.

## conn.log Example

Input:

```
#path	conn
#fields	ts	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	orig_bytes	resp_bytes	duration
1705312201.123456	10.0.0.1	54321	93.184.216.34	443	tcp	1500	32000	1.5
```

Produces a `NetworkConnection` with:
- `protocol_id`: 6 (TCP)
- `bytes_out`: 1500
- `bytes_in`: 32000
- `duration_us`: 1,500,000

## notice.log Example

Input:

```
#path	notice
#fields	ts	note	msg	src	dst	p	n
1705312201.123456	Scan::Port_Scan	Port scan detected	10.0.0.1	-	-	-
```

Produces a `DetectionFinding` with:
- `title`: "Scan::Port_Scan"
- `severity`: Medium
- `risk_score`: 50

## Usage

```bash
nous-engine --input /var/log/zeek/current/conn.log --adapter zeek
```

For multiple Zeek log types, concatenate them (each file includes its own headers):

```bash
cat /var/log/zeek/current/*.log | nous-engine --adapter zeek
```
