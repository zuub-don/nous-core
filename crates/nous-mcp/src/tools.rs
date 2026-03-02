//! MCP tool definitions and gRPC proxy execution.

use serde_json::{json, Value};
use tonic::transport::Channel;
use tracing::debug;

use nous_proto::{
    GetStatusRequest, NousServiceClient, ObserveRequest, QueryEntityRequest, QueryEventsRequest,
    SubmitActionRequest, SubmitVerdictRequest,
};

/// Tool definition for the MCP tools/list response.
pub fn tool_definitions() -> Value {
    json!({
        "tools": [
            {
                "name": "get_status",
                "description": "Get current engine status: event count, active findings, uptime, version.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "query_events",
                "description": "Query recent security events with optional filters.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "class_uid": {
                            "type": "integer",
                            "description": "OCSF class UID filter (0 = all)"
                        },
                        "min_severity": {
                            "type": "integer",
                            "description": "Minimum severity level (0-5)"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum events to return (default 100)"
                        }
                    },
                    "required": []
                }
            },
            {
                "name": "observe",
                "description": "Generate a context window summarizing the current security situation.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "token_budget": {
                            "type": "integer",
                            "description": "Token budget (1024/2048/4096/8192/16384, default 4096)"
                        },
                        "format": {
                            "type": "string",
                            "description": "Output format: structured_json, narrative, delta",
                            "enum": ["structured_json", "narrative", "delta"]
                        }
                    },
                    "required": []
                }
            },
            {
                "name": "query_entity",
                "description": "Look up an entity's risk score by type and value.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "entity_type": {
                            "type": "string",
                            "description": "Entity type: ip_address, domain, hostname, user, process, file, url",
                            "enum": ["ip_address", "domain", "hostname", "user", "process", "file", "url"]
                        },
                        "value": {
                            "type": "string",
                            "description": "Entity value (e.g., IP address, domain name)"
                        }
                    },
                    "required": ["entity_type", "value"]
                }
            },
            {
                "name": "submit_verdict",
                "description": "Submit a triage verdict for a security finding.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "UUID of the finding to verdict"
                        },
                        "verdict": {
                            "type": "string",
                            "description": "Triage verdict",
                            "enum": ["true_positive", "false_positive", "benign", "needs_investigation"]
                        },
                        "agent_id": {
                            "type": "string",
                            "description": "ID of the agent submitting the verdict"
                        },
                        "reasoning": {
                            "type": "string",
                            "description": "Explanation for the verdict"
                        },
                        "confidence": {
                            "type": "number",
                            "description": "Confidence score (0.0-1.0)"
                        }
                    },
                    "required": ["finding_id", "verdict", "agent_id", "reasoning", "confidence"]
                }
            },
            {
                "name": "submit_action",
                "description": "Submit a response action for a security entity.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action_type": {
                            "type": "string",
                            "description": "Action type",
                            "enum": ["escalate", "suppress", "isolate", "block", "allowlist"]
                        },
                        "agent_id": {
                            "type": "string",
                            "description": "ID of the agent submitting the action"
                        },
                        "target_entity_type": {
                            "type": "string",
                            "description": "Entity type of the target"
                        },
                        "target_value": {
                            "type": "string",
                            "description": "Value of the target entity"
                        },
                        "reasoning": {
                            "type": "string",
                            "description": "Explanation for the action"
                        }
                    },
                    "required": ["action_type", "agent_id", "target_entity_type", "target_value", "reasoning"]
                }
            }
        ]
    })
}

/// Execute a tool call by proxying to nous-engine via gRPC.
pub async fn execute_tool(
    client: &mut NousServiceClient<Channel>,
    tool_name: &str,
    arguments: &Value,
) -> Result<Value, String> {
    debug!(tool = tool_name, "executing tool call");

    match tool_name {
        "get_status" => execute_get_status(client).await,
        "query_events" => execute_query_events(client, arguments).await,
        "observe" => execute_observe(client, arguments).await,
        "query_entity" => execute_query_entity(client, arguments).await,
        "submit_verdict" => execute_submit_verdict(client, arguments).await,
        "submit_action" => execute_submit_action(client, arguments).await,
        other => Err(format!("unknown tool: {other}")),
    }
}

async fn execute_get_status(client: &mut NousServiceClient<Channel>) -> Result<Value, String> {
    let response = client
        .get_status(GetStatusRequest {})
        .await
        .map_err(|e| format!("gRPC error: {e}"))?;

    let status = response.into_inner();
    Ok(json!({
        "event_count": status.event_count,
        "active_findings": status.active_findings,
        "uptime_seconds": status.uptime_seconds,
        "version": status.version
    }))
}

async fn execute_query_events(
    client: &mut NousServiceClient<Channel>,
    args: &Value,
) -> Result<Value, String> {
    let response = client
        .query_events(QueryEventsRequest {
            class_uid: args["class_uid"].as_u64().unwrap_or(0) as u32,
            min_severity: args["min_severity"].as_u64().unwrap_or(0) as u32,
            limit: args["limit"].as_u64().unwrap_or(100) as u32,
        })
        .await
        .map_err(|e| format!("gRPC error: {e}"))?;

    let events = response.into_inner();
    let parsed: Vec<Value> = events
        .events
        .iter()
        .filter_map(|e| serde_json::from_str(e).ok())
        .collect();

    Ok(json!({
        "events": parsed,
        "total": events.total
    }))
}

async fn execute_observe(
    client: &mut NousServiceClient<Channel>,
    args: &Value,
) -> Result<Value, String> {
    let response = client
        .observe(ObserveRequest {
            token_budget: args["token_budget"].as_u64().unwrap_or(0) as u32,
            format: args["format"].as_str().unwrap_or("").to_string(),
        })
        .await
        .map_err(|e| format!("gRPC error: {e}"))?;

    let window = response.into_inner();
    serde_json::from_str(&window.context_window)
        .map_err(|e| format!("failed to parse context window: {e}"))
}

async fn execute_query_entity(
    client: &mut NousServiceClient<Channel>,
    args: &Value,
) -> Result<Value, String> {
    let entity_type = args["entity_type"]
        .as_str()
        .ok_or("missing entity_type")?
        .to_string();
    let value = args["value"].as_str().ok_or("missing value")?.to_string();

    let response = client
        .query_entity(QueryEntityRequest {
            entity_type: entity_type.clone(),
            value: value.clone(),
        })
        .await
        .map_err(|e| format!("gRPC error: {e}"))?;

    let entity = response.into_inner();
    Ok(json!({
        "found": entity.found,
        "entity_type": entity.entity_type,
        "value": entity.value,
        "risk_score": entity.risk_score
    }))
}

async fn execute_submit_verdict(
    client: &mut NousServiceClient<Channel>,
    args: &Value,
) -> Result<Value, String> {
    let response = client
        .submit_verdict(SubmitVerdictRequest {
            finding_id: args["finding_id"]
                .as_str()
                .ok_or("missing finding_id")?
                .to_string(),
            verdict: args["verdict"]
                .as_str()
                .ok_or("missing verdict")?
                .to_string(),
            agent_id: args["agent_id"]
                .as_str()
                .ok_or("missing agent_id")?
                .to_string(),
            reasoning: args["reasoning"]
                .as_str()
                .ok_or("missing reasoning")?
                .to_string(),
            confidence: args["confidence"].as_f64().unwrap_or(0.0),
        })
        .await
        .map_err(|e| format!("gRPC error: {e}"))?;

    let verdict = response.into_inner();
    Ok(json!({
        "verdict_id": verdict.verdict_id,
        "accepted": verdict.accepted
    }))
}

async fn execute_submit_action(
    client: &mut NousServiceClient<Channel>,
    args: &Value,
) -> Result<Value, String> {
    let response = client
        .submit_action(SubmitActionRequest {
            action_type: args["action_type"]
                .as_str()
                .ok_or("missing action_type")?
                .to_string(),
            agent_id: args["agent_id"]
                .as_str()
                .ok_or("missing agent_id")?
                .to_string(),
            target_entity_type: args["target_entity_type"]
                .as_str()
                .ok_or("missing target_entity_type")?
                .to_string(),
            target_value: args["target_value"]
                .as_str()
                .ok_or("missing target_value")?
                .to_string(),
            reasoning: args["reasoning"]
                .as_str()
                .ok_or("missing reasoning")?
                .to_string(),
        })
        .await
        .map_err(|e| format!("gRPC error: {e}"))?;

    let action = response.into_inner();
    Ok(json!({
        "action_id": action.action_id,
        "accepted": action.accepted
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_definitions_are_valid_json() {
        let defs = tool_definitions();
        let tools = defs["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 6);

        // Verify all tools have required fields
        for tool in tools {
            assert!(tool["name"].is_string());
            assert!(tool["description"].is_string());
            assert!(tool["inputSchema"].is_object());
        }
    }

    #[test]
    fn tool_names_are_correct() {
        let defs = tool_definitions();
        let tools = defs["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"get_status"));
        assert!(names.contains(&"query_events"));
        assert!(names.contains(&"observe"));
        assert!(names.contains(&"query_entity"));
        assert!(names.contains(&"submit_verdict"));
        assert!(names.contains(&"submit_action"));
    }

    #[test]
    fn tool_schemas_have_required_fields() {
        let defs = tool_definitions();
        let tools = defs["tools"].as_array().unwrap();

        // query_entity requires entity_type and value
        let qe = tools.iter().find(|t| t["name"] == "query_entity").unwrap();
        let required = qe["inputSchema"]["required"].as_array().unwrap();
        assert!(required.contains(&json!("entity_type")));
        assert!(required.contains(&json!("value")));

        // submit_verdict requires 5 fields
        let sv = tools
            .iter()
            .find(|t| t["name"] == "submit_verdict")
            .unwrap();
        let required = sv["inputSchema"]["required"].as_array().unwrap();
        assert_eq!(required.len(), 5);

        // submit_action requires 5 fields
        let sa = tools.iter().find(|t| t["name"] == "submit_action").unwrap();
        let required = sa["inputSchema"]["required"].as_array().unwrap();
        assert_eq!(required.len(), 5);
    }

    #[test]
    fn verdict_tool_has_enum_constraint() {
        let defs = tool_definitions();
        let tools = defs["tools"].as_array().unwrap();
        let sv = tools
            .iter()
            .find(|t| t["name"] == "submit_verdict")
            .unwrap();
        let verdict_enum = sv["inputSchema"]["properties"]["verdict"]["enum"]
            .as_array()
            .unwrap();
        assert_eq!(verdict_enum.len(), 4);
        assert!(verdict_enum.contains(&json!("true_positive")));
        assert!(verdict_enum.contains(&json!("false_positive")));
        assert!(verdict_enum.contains(&json!("benign")));
        assert!(verdict_enum.contains(&json!("needs_investigation")));
    }
}
