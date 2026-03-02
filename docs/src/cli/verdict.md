# nous-ctl verdict

Submit a triage verdict for a security finding.

## Usage

```
nous-ctl verdict <FINDING_ID> <VERDICT> [OPTIONS]
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `FINDING_ID` | Yes | UUID of the finding to verdict |
| `VERDICT` | Yes | Triage verdict (see table below) |

### Verdict Values

| Verdict | Description |
|---------|-------------|
| `true_positive` | Confirmed malicious — escalate |
| `false_positive` | Not malicious — suppress future occurrences |
| `benign` | Legitimate activity — no action needed |
| `needs_investigation` | Insufficient information — keep active |

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--agent <ID>` | `nous-ctl` | Agent ID submitting the verdict |
| `--reasoning <R>` | `manual` | Reasoning text explaining the verdict |
| `--confidence <N>` | `1.0` | Confidence score (0.0 to 1.0) |

## Examples

```bash
# Confirm a finding as malicious
nous-ctl verdict 01944abc-def0-7000-8000-000000000001 true_positive

# Mark as false positive with reasoning
nous-ctl verdict 01944abc-def0-7000-8000-000000000001 false_positive \
  --reasoning "known scanner noise" --confidence 0.9

# Flag for further investigation
nous-ctl verdict 01944abc-def0-7000-8000-000000000001 needs_investigation \
  --agent analyst-bot --reasoning "unusual pattern, need more data"
```

## Output: Accepted

```
verdict accepted: 01944def-0000-7000-8000-000000000002
```

The returned UUID is the verdict ID, distinct from the finding ID.

## Output: Rejected

```
verdict rejected
```

A verdict may be rejected if the finding ID is unknown or already resolved.
