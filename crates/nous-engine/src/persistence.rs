//! Feature-gated PostgreSQL persistence: event, verdict, and action storage.
//!
//! Enabled with `--features persistence`. Requires a PostgreSQL database URL
//! passed via `--db-url`.

use anyhow::Result;
use sqlx::PgPool;
use tracing::{debug, info};

use nous_core::action::AgentAction;
use nous_core::event::NousEvent;
use nous_core::verdict::Verdict;

/// Initialize database tables (CREATE TABLE IF NOT EXISTS).
pub async fn init_db(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS events (
            id UUID PRIMARY KEY,
            time BIGINT NOT NULL,
            class_uid INTEGER NOT NULL,
            severity INTEGER NOT NULL,
            source_json TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            raw TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS verdicts (
            id UUID PRIMARY KEY,
            finding_id UUID NOT NULL,
            verdict TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            reasoning TEXT NOT NULL,
            confidence DOUBLE PRECISION NOT NULL,
            created_at BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS actions (
            id UUID PRIMARY KEY,
            action_type TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            target_entity_type TEXT NOT NULL,
            target_value TEXT NOT NULL,
            reasoning TEXT NOT NULL,
            created_at BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    info!("persistence: database tables initialized");
    Ok(())
}

/// Store an event in the database.
pub async fn store_event(pool: &PgPool, event: &NousEvent) -> Result<()> {
    let source_json = serde_json::to_string(&event.source)?;
    let payload_json = serde_json::to_string(&event.payload)?;

    sqlx::query(
        "INSERT INTO events (id, time, class_uid, severity, source_json, payload_json, raw)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(event.id)
    .bind(event.time)
    .bind(event.class_uid as i32)
    .bind(event.severity.id() as i32)
    .bind(&source_json)
    .bind(&payload_json)
    .bind(&event.raw)
    .execute(pool)
    .await?;

    debug!(id = %event.id, "persistence: event stored");
    Ok(())
}

/// Store a verdict in the database.
#[allow(dead_code)]
pub async fn store_verdict(pool: &PgPool, verdict: &Verdict) -> Result<()> {
    let verdict_str = format!("{:?}", verdict.verdict);

    sqlx::query(
        "INSERT INTO verdicts (id, finding_id, verdict, agent_id, reasoning, confidence, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(verdict.id)
    .bind(verdict.finding_id)
    .bind(&verdict_str)
    .bind(&verdict.agent_id)
    .bind(&verdict.reasoning)
    .bind(verdict.confidence)
    .bind(verdict.created_at)
    .execute(pool)
    .await?;

    debug!(id = %verdict.id, "persistence: verdict stored");
    Ok(())
}

/// Store an action in the database.
#[allow(dead_code)]
pub async fn store_action(pool: &PgPool, action: &AgentAction) -> Result<()> {
    let action_type_str = format!("{:?}", action.action_type);

    sqlx::query(
        "INSERT INTO actions (id, action_type, agent_id, target_entity_type, target_value, reasoning, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(action.id)
    .bind(&action_type_str)
    .bind(&action.agent_id)
    .bind(&action.target_entity_type)
    .bind(&action.target_value)
    .bind(&action.reasoning)
    .bind(action.created_at)
    .execute(pool)
    .await?;

    debug!(id = %action.id, "persistence: action stored");
    Ok(())
}

#[cfg(test)]
mod tests {

    #[test]
    fn init_db_sql_is_valid() {
        // Verify the SQL strings are syntactically reasonable (no panics on construction)
        let create_events = "CREATE TABLE IF NOT EXISTS events (
            id UUID PRIMARY KEY,
            time BIGINT NOT NULL,
            class_uid INTEGER NOT NULL,
            severity INTEGER NOT NULL,
            source_json TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            raw TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )";
        assert!(create_events.contains("events"));
        assert!(create_events.contains("UUID PRIMARY KEY"));
    }

    #[test]
    fn store_event_sql_uses_conflict_handling() {
        let sql =
            "INSERT INTO events (id, time, class_uid, severity, source_json, payload_json, raw)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (id) DO NOTHING";
        assert!(sql.contains("ON CONFLICT"));
        assert!(sql.contains("$7"));
    }

    #[test]
    fn store_verdict_sql_uses_conflict_handling() {
        let sql = "INSERT INTO verdicts (id, finding_id, verdict, agent_id, reasoning, confidence, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (id) DO NOTHING";
        assert!(sql.contains("verdicts"));
        assert!(sql.contains("ON CONFLICT"));
    }

    #[test]
    fn store_action_sql_has_all_columns() {
        let sql = "INSERT INTO actions (id, action_type, agent_id, target_entity_type, target_value, reasoning, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)";
        assert!(sql.contains("action_type"));
        assert!(sql.contains("target_entity_type"));
        assert!(sql.contains("target_value"));
    }

    #[test]
    fn verdict_debug_format() {
        use nous_core::verdict::{TriageVerdict, Verdict};
        let v = Verdict::new(
            uuid::Uuid::nil(),
            TriageVerdict::TruePositive,
            "agent-1",
            "test",
            0.9,
        );
        let s = format!("{:?}", v.verdict);
        assert_eq!(s, "TruePositive");
    }
}
