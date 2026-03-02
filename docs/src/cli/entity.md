# nous-ctl entity

Query the risk score and metadata for a tracked entity.

## Usage

```
nous-ctl entity <TYPE> <VALUE>
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `TYPE` | Yes | Entity type (see table below) |
| `VALUE` | Yes | Entity value (e.g., IP address, domain name) |

### Entity Types

| Type | Example Value |
|------|---------------|
| `ip_address` | `10.0.0.1` |
| `domain` | `evil.com` |
| `hostname` | `workstation-42` |
| `user` | `root` |
| `process` | `sshd` |
| `file` | `/tmp/malware.exe` |
| `url` | `https://evil.com/payload` |

## Examples

```bash
nous-ctl entity ip_address 10.0.0.1
nous-ctl entity domain evil.com
nous-ctl entity user root
```

## Output: Entity Found

```
entity:     ip_address = 10.0.0.1
risk_score: 75
```

## Output: Entity Not Found

```
entity not found: ip_address = 10.0.0.1
```

An entity is tracked only after it has been seen in at least one event or had its risk score explicitly set via a verdict or action.
