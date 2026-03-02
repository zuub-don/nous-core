//! nous-mcp: MCP server that bridges Nous Core API to AI agents via JSON-RPC 2.0 over stdio.

mod mcp;
mod tools;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use nous_proto::NousServiceClient;

use crate::mcp::{JsonRpcResponse, INTERNAL_ERROR, METHOD_NOT_FOUND};

#[tokio::main]
async fn main() -> Result<()> {
    // Log to stderr so stdout stays clean for JSON-RPC
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("nous=info".parse()?))
        .with_writer(std::io::stderr)
        .init();

    let engine_addr =
        std::env::var("NOUS_ENGINE_ADDR").unwrap_or_else(|_| "http://127.0.0.1:50051".into());

    info!(addr = %engine_addr, "nous-mcp v{} starting", env!("CARGO_PKG_VERSION"));

    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    // Lazily connect to the engine on first tool call
    let mut client: Option<NousServiceClient<tonic::transport::Channel>> = None;

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let request = match mcp::parse_request(&line) {
            Ok(req) => req,
            Err(e) => {
                let resp = JsonRpcResponse::error(None, -32700, e);
                println!("{}", serde_json::to_string(&resp)?);
                continue;
            }
        };

        let response = match request.method.as_str() {
            "initialize" => JsonRpcResponse::success(
                request.id.clone(),
                serde_json::json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "nous-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }),
            ),

            "tools/list" => JsonRpcResponse::success(request.id.clone(), tools::tool_definitions()),

            "tools/call" => {
                let params = request.params.as_ref();
                let tool_name = params.and_then(|p| p["name"].as_str()).unwrap_or("");
                let arguments = params
                    .and_then(|p| p.get("arguments"))
                    .cloned()
                    .unwrap_or(serde_json::json!({}));

                // Lazily connect
                if client.is_none() {
                    match NousServiceClient::connect(engine_addr.clone()).await {
                        Ok(c) => client = Some(c),
                        Err(e) => {
                            error!(error = %e, "failed to connect to engine");
                            let resp = JsonRpcResponse::error(
                                request.id.clone(),
                                INTERNAL_ERROR,
                                format!("failed to connect to engine: {e}"),
                            );
                            println!("{}", serde_json::to_string(&resp)?);
                            continue;
                        }
                    }
                }

                match tools::execute_tool(
                    client.as_mut().expect("client set above"),
                    tool_name,
                    &arguments,
                )
                .await
                {
                    Ok(result) => JsonRpcResponse::success(
                        request.id.clone(),
                        serde_json::json!({
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&result).unwrap_or_default()
                            }]
                        }),
                    ),
                    Err(e) => JsonRpcResponse::error(request.id.clone(), INTERNAL_ERROR, e),
                }
            }

            _ => JsonRpcResponse::error(
                request.id.clone(),
                METHOD_NOT_FOUND,
                format!("unknown method: {}", request.method),
            ),
        };

        println!("{}", serde_json::to_string(&response)?);
    }

    info!("nous-mcp shutting down");
    Ok(())
}
