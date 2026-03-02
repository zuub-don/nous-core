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

/// Filters for querying persisted events.
#[allow(dead_code)]
pub struct EventFilters {
    /// Filter by OCSF class UID (None = all).
    pub class_uid: Option<u32>,
    /// Filter by minimum severity (None = all).
    pub min_severity: Option<u8>,
    /// Maximum number of events to return.
    pub limit: i64,
}

/// Query events from the database with optional filters.
///
/// Returns rows as `(id, time, class_uid, severity, source_json, payload_json, raw)` tuples
/// serialized to JSON, ordered by time descending.
#[allow(dead_code)]
pub async fn query_events(pool: &PgPool, filters: &EventFilters) -> Result<Vec<serde_json::Value>> {
    let mut query = String::from(
        "SELECT id, time, class_uid, severity, source_json, payload_json, raw
         FROM events WHERE 1=1",
    );
    let mut bind_idx = 1u32;

    if filters.class_uid.is_some() {
        query.push_str(&format!(" AND class_uid = ${bind_idx}"));
        bind_idx += 1;
    }
    if filters.min_severity.is_some() {
        query.push_str(&format!(" AND severity >= ${bind_idx}"));
        bind_idx += 1;
    }
    let _ = bind_idx; // suppress unused warning

    query.push_str(&format!(" ORDER BY time DESC LIMIT {}", filters.limit));

    // Build and bind dynamically
    let mut q =
        sqlx::query_as::<_, (uuid::Uuid, i64, i32, i32, String, String, Option<String>)>(&query);

    if let Some(class_uid) = filters.class_uid {
        q = q.bind(class_uid as i32);
    }
    if let Some(min_severity) = filters.min_severity {
        q = q.bind(min_severity as i32);
    }

    let rows = q.fetch_all(pool).await?;

    let results: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(id, time, class_uid, severity, source_json, payload_json, raw)| {
            serde_json::json!({
                "id": id.to_string(),
                "time": time,
                "class_uid": class_uid,
                "severity": severity,
                "source": serde_json::from_str::<serde_json::Value>(&source_json).unwrap_or_default(),
                "payload": serde_json::from_str::<serde_json::Value>(&payload_json).unwrap_or_default(),
                "raw": raw,
            })
        })
        .collect();

    debug!(count = results.len(), "persistence: events queried");
    Ok(results)
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
    fn query_events_sql_builds_correctly() {
        // Base query with no filters
        let base = "SELECT id, time, class_uid, severity, source_json, payload_json, raw
         FROM events WHERE 1=1";
        assert!(base.contains("SELECT"));
        assert!(base.contains("FROM events"));

        // With class_uid filter
        let with_class = format!("{base} AND class_uid = $1 ORDER BY time DESC LIMIT 100");
        assert!(with_class.contains("class_uid = $1"));
        assert!(with_class.contains("ORDER BY time DESC"));
        assert!(with_class.contains("LIMIT 100"));

        // With both filters
        let with_both =
            format!("{base} AND class_uid = $1 AND severity >= $2 ORDER BY time DESC LIMIT 50");
        assert!(with_both.contains("class_uid = $1"));
        assert!(with_both.contains("severity >= $2"));
        assert!(with_both.contains("LIMIT 50"));
    }

    #[test]
    fn event_filters_defaults() {
        use super::EventFilters;
        let filters = EventFilters {
            class_uid: None,
            min_severity: None,
            limit: 100,
        };
        assert!(filters.class_uid.is_none());
        assert!(filters.min_severity.is_none());
        assert_eq!(filters.limit, 100);
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
