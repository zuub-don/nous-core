# Persistence

By default, Nous Core operates entirely in-memory. The optional `persistence` feature enables PostgreSQL-backed event storage.

## Enabling Persistence

Build with the `persistence` feature flag:

```bash
cargo build --workspace --release --features persistence
```

## Configuration

Pass the database URL to `nous-engine`:

```bash
nous-engine \
  --input /var/log/suricata/eve.json \
  --adapter suricata \
  --db-url postgres://user:password@localhost:5432/nous
```

## Schema Auto-Initialization

When `--db-url` is provided, `nous-engine` automatically creates the required tables on startup if they don't exist. No manual migrations are needed.

## Database Tables

| Table | Description |
|-------|-------------|
| `events` | Stored `NousEvent` records with JSON payload, indexed by class_uid and time |

## Query Events from Storage

With persistence enabled, `nous-ctl events` and the `query_events` MCP tool can read from the database, providing access to historical events beyond the in-memory buffer.

## PostgreSQL Requirements

- PostgreSQL 14 or later
- The `sqlx` driver connects asynchronously via `tokio`
- Connection pooling is handled automatically

## Example Setup

```bash
# Create the database
createdb nous

# Start the engine with persistence
nous-engine \
  --input /var/log/suricata/eve.json \
  --adapter suricata \
  --db-url postgres://localhost/nous

# Query historical events
nous-ctl events --limit 100
```
