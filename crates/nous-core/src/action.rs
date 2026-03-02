//! Response actions submitted by agents.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Type of response action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    /// Escalate to a human analyst.
    Escalate,
    /// Suppress future alerts for this pattern.
    Suppress,
    /// Isolate the target entity from the network.
    Isolate,
    /// Block the target entity.
    Block,
    /// Add the target entity to an allowlist.
    Allowlist,
}

/// A response action submitted by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAction {
    /// Unique action identifier.
    pub id: Uuid,
    /// The type of action to perform.
    pub action_type: ActionType,
    /// ID of the agent that submitted this action.
    pub agent_id: String,
    /// Entity type of the target (e.g., "ip_address", "domain").
    pub target_entity_type: String,
    /// Value of the target entity.
    pub target_value: String,
    /// Agent's reasoning for the action.
    pub reasoning: String,
    /// When this action was created (epoch nanos).
    pub created_at: i64,
}

impl AgentAction {
    /// Create a new action with a fresh UUIDv7 and current timestamp.
    pub fn new(
        action_type: ActionType,
        agent_id: impl Into<String>,
        target_entity_type: impl Into<String>,
        target_value: impl Into<String>,
        reasoning: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            action_type,
            agent_id: agent_id.into(),
            target_entity_type: target_entity_type.into(),
            target_value: target_value.into(),
            reasoning: reasoning.into(),
            created_at: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_creation() {
        let a = AgentAction::new(
            ActionType::Block,
            "agent-1",
            "ip_address",
            "10.0.0.99",
            "confirmed C2 beacon",
        );
        assert!(!a.id.is_nil());
        assert_eq!(a.action_type, ActionType::Block);
        assert_eq!(a.agent_id, "agent-1");
        assert_eq!(a.target_entity_type, "ip_address");
        assert_eq!(a.target_value, "10.0.0.99");
        assert!(a.created_at > 0);
    }

    #[test]
    fn action_serde_roundtrip() {
        let a = AgentAction::new(
            ActionType::Isolate,
            "agent-2",
            "hostname",
            "workstation-42",
            "lateral movement detected",
        );
        let json = serde_json::to_string(&a).unwrap();
        let deser: AgentAction = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.id, a.id);
        assert_eq!(deser.action_type, ActionType::Isolate);
        assert_eq!(deser.target_value, "workstation-42");
    }

    #[test]
    fn action_type_all_variants_serde() {
        let variants = [
            ActionType::Escalate,
            ActionType::Suppress,
            ActionType::Isolate,
            ActionType::Block,
            ActionType::Allowlist,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let deser: ActionType = serde_json::from_str(&json).unwrap();
            assert_eq!(&deser, variant);
        }
    }
}
