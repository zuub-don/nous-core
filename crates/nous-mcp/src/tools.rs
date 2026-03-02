//! MCP tool definitions and gRPC proxy execution.

use serde_json::{json, Value};
use tonic::transport::Channel;
use tracing::debug;

use nous_proto::{GetStatusRequest, NousServiceClient, ObserveRequest, QueryEventsRequest};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_definitions_are_valid_json() {
        let defs = tool_definitions();
        let tools = defs["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 3);

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
    }
}
