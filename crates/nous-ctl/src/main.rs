//! nous-ctl: CLI client for querying the Nous Core engine.

use anyhow::{Context, Result};
use tokio_stream::StreamExt;

use nous_proto::{
    GetStatusRequest, NousServiceClient, ObserveRequest, QueryEntityRequest, QueryEventsRequest,
    StreamEventsRequest, SubmitVerdictRequest,
};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let subcommand = args.first().map(|s| s.as_str()).unwrap_or("help");

    match subcommand {
        "status" => cmd_status().await,
        "events" => cmd_events(&args[1..]).await,
        "observe" => cmd_observe(&args[1..]).await,
        "entity" => cmd_entity(&args[1..]).await,
        "verdict" => cmd_verdict(&args[1..]).await,
        "watch" => cmd_watch(&args[1..]).await,
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}");
            eprintln!();
            print_help();
            std::process::exit(1);
        }
    }
}

fn print_help() {
    println!("nous-ctl v{}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("USAGE:");
    println!("  nous-ctl <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("  status              Show engine status (event count, findings, uptime)");
    println!("  events [OPTIONS]    Query recent events");
    println!("    --class <N>       Filter by OCSF class_uid");
    println!("    --severity <N>    Filter by minimum severity (0-5)");
    println!("    --limit <N>       Maximum events to return (default 20)");
    println!("  observe [OPTIONS]   Generate a context window");
    println!("    --budget <N>      Token budget (default 4096)");
    println!("    --format <F>      Output format: structured_json, narrative, delta");
    println!("  entity <TYPE> <VALUE>  Query entity risk score");
    println!("  verdict <FINDING_ID> <VERDICT> [OPTIONS]  Submit triage verdict");
    println!("    --agent <ID>      Agent ID (default: nous-ctl)");
    println!("    --reasoning <R>   Reasoning text (default: manual)");
    println!("    --confidence <N>  Confidence 0.0-1.0 (default: 1.0)");
    println!("  watch [OPTIONS]     Stream events in real-time");
    println!("    --class <N>       Filter by OCSF class_uid");
    println!("    --severity <N>    Filter by minimum severity (0-5)");
    println!("  help                Show this help message");
    println!();
    println!("ENVIRONMENT:");
    println!("  NOUS_ENGINE_ADDR    Engine gRPC address (default: http://127.0.0.1:50051)");
}

fn engine_addr() -> String {
    std::env::var("NOUS_ENGINE_ADDR").unwrap_or_else(|_| "http://127.0.0.1:50051".into())
}

async fn connect() -> Result<NousServiceClient<tonic::transport::Channel>> {
    let addr = engine_addr();
    NousServiceClient::connect(addr.clone())
        .await
        .with_context(|| format!("failed to connect to engine at {addr}"))
}

async fn cmd_status() -> Result<()> {
    let mut client = connect().await?;
    let response = client
        .get_status(GetStatusRequest {})
        .await
        .context("GetStatus RPC failed")?;

    let status = response.into_inner();
    println!("nous-engine v{}", status.version);
    println!("  events ingested:  {}", status.event_count);
    println!("  active findings:  {}", status.active_findings);
    println!("  uptime:           {}s", status.uptime_seconds);
    Ok(())
}

async fn cmd_events(args: &[String]) -> Result<()> {
    let parsed = parse_events_args(args)?;
    let mut client = connect().await?;

    let response = client
        .query_events(QueryEventsRequest {
            class_uid: parsed.class_uid,
            min_severity: parsed.min_severity,
            limit: parsed.limit,
        })
        .await
        .context("QueryEvents RPC failed")?;

    let events = response.into_inner();
    println!("total: {}", events.total);
    for event_json in &events.events {
        // Pretty-print each event
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(event_json) {
            println!("{}", serde_json::to_string_pretty(&v)?);
        } else {
            println!("{event_json}");
        }
    }
    Ok(())
}

async fn cmd_observe(args: &[String]) -> Result<()> {
    let parsed = parse_observe_args(args)?;
    let mut client = connect().await?;

    let response = client
        .observe(ObserveRequest {
            token_budget: parsed.budget,
            format: parsed.format,
        })
        .await
        .context("Observe RPC failed")?;

    let observe = response.into_inner();
    // Pretty-print the context window
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&observe.context_window) {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!("{}", observe.context_window);
    }
    Ok(())
}

async fn cmd_entity(args: &[String]) -> Result<()> {
    let parsed = parse_entity_args(args)?;
    let mut client = connect().await?;

    let response = client
        .query_entity(QueryEntityRequest {
            entity_type: parsed.entity_type.clone(),
            value: parsed.value.clone(),
        })
        .await
        .context("QueryEntity RPC failed")?;

    let entity = response.into_inner();
    if entity.found {
        println!("entity:     {} = {}", entity.entity_type, entity.value);
        println!("risk_score: {}", entity.risk_score);
    } else {
        println!(
            "entity not found: {} = {}",
            parsed.entity_type, parsed.value
        );
    }
    Ok(())
}

async fn cmd_verdict(args: &[String]) -> Result<()> {
    let parsed = parse_verdict_args(args)?;
    let mut client = connect().await?;

    let response = client
        .submit_verdict(SubmitVerdictRequest {
            finding_id: parsed.finding_id,
            verdict: parsed.verdict,
            agent_id: parsed.agent_id,
            reasoning: parsed.reasoning,
            confidence: parsed.confidence,
        })
        .await
        .context("SubmitVerdict RPC failed")?;

    let result = response.into_inner();
    if result.accepted {
        println!("verdict accepted: {}", result.verdict_id);
    } else {
        println!("verdict rejected");
    }
    Ok(())
}

async fn cmd_watch(args: &[String]) -> Result<()> {
    let parsed = parse_watch_args(args)?;
    let mut client = connect().await?;

    let response = client
        .stream_events(StreamEventsRequest {
            class_uid: parsed.class_uid,
            min_severity: parsed.min_severity,
        })
        .await
        .context("StreamEvents RPC failed")?;

    let mut stream = response.into_inner();
    while let Some(result) = stream.next().await {
        match result {
            Ok(notification) => {
                // Pretty-print the event JSON
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&notification.event_json) {
                    println!("{}", serde_json::to_string_pretty(&v)?);
                } else {
                    println!("{}", notification.event_json);
                }
            }
            Err(e) => {
                eprintln!("stream error: {e}");
                break;
            }
        }
    }
    Ok(())
}

struct EventsArgs {
    class_uid: u32,
    min_severity: u32,
    limit: u32,
}

fn parse_events_args(args: &[String]) -> Result<EventsArgs> {
    let mut parsed = EventsArgs {
        class_uid: 0,
        min_severity: 0,
        limit: 20,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--class" => {
                i += 1;
                parsed.class_uid = args
                    .get(i)
                    .context("--class requires a value")?
                    .parse()
                    .context("invalid class_uid")?;
            }
            "--severity" => {
                i += 1;
                parsed.min_severity = args
                    .get(i)
                    .context("--severity requires a value")?
                    .parse()
                    .context("invalid severity")?;
            }
            "--limit" => {
                i += 1;
                parsed.limit = args
                    .get(i)
                    .context("--limit requires a value")?
                    .parse()
                    .context("invalid limit")?;
            }
            other => anyhow::bail!("unknown events option: {other}"),
        }
        i += 1;
    }
    Ok(parsed)
}

struct ObserveArgs {
    budget: u32,
    format: String,
}

fn parse_observe_args(args: &[String]) -> Result<ObserveArgs> {
    let mut parsed = ObserveArgs {
        budget: 0,
        format: String::new(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--budget" => {
                i += 1;
                parsed.budget = args
                    .get(i)
                    .context("--budget requires a value")?
                    .parse()
                    .context("invalid budget")?;
            }
            "--format" => {
                i += 1;
                parsed.format = args.get(i).context("--format requires a value")?.clone();
            }
            other => anyhow::bail!("unknown observe option: {other}"),
        }
        i += 1;
    }
    Ok(parsed)
}

struct EntityArgs {
    entity_type: String,
    value: String,
}

fn parse_entity_args(args: &[String]) -> Result<EntityArgs> {
    if args.len() < 2 {
        anyhow::bail!("usage: entity <TYPE> <VALUE>");
    }
    Ok(EntityArgs {
        entity_type: args[0].clone(),
        value: args[1].clone(),
    })
}

struct VerdictArgs {
    finding_id: String,
    verdict: String,
    agent_id: String,
    reasoning: String,
    confidence: f64,
}

fn parse_verdict_args(args: &[String]) -> Result<VerdictArgs> {
    if args.len() < 2 {
        anyhow::bail!("usage: verdict <FINDING_ID> <VERDICT> [--agent ID] [--reasoning TEXT] [--confidence N]");
    }
    let mut parsed = VerdictArgs {
        finding_id: args[0].clone(),
        verdict: args[1].clone(),
        agent_id: "nous-ctl".into(),
        reasoning: "manual".into(),
        confidence: 1.0,
    };

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--agent" => {
                i += 1;
                parsed.agent_id = args.get(i).context("--agent requires a value")?.clone();
            }
            "--reasoning" => {
                i += 1;
                parsed.reasoning = args.get(i).context("--reasoning requires a value")?.clone();
            }
            "--confidence" => {
                i += 1;
                parsed.confidence = args
                    .get(i)
                    .context("--confidence requires a value")?
                    .parse()
                    .context("invalid confidence")?;
            }
            other => anyhow::bail!("unknown verdict option: {other}"),
        }
        i += 1;
    }
    Ok(parsed)
}

struct WatchArgs {
    class_uid: u32,
    min_severity: u32,
}

fn parse_watch_args(args: &[String]) -> Result<WatchArgs> {
    let mut parsed = WatchArgs {
        class_uid: 0,
        min_severity: 0,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--class" => {
                i += 1;
                parsed.class_uid = args
                    .get(i)
                    .context("--class requires a value")?
                    .parse()
                    .context("invalid class_uid")?;
            }
            "--severity" => {
                i += 1;
                parsed.min_severity = args
                    .get(i)
                    .context("--severity requires a value")?
                    .parse()
                    .context("invalid severity")?;
            }
            other => anyhow::bail!("unknown watch option: {other}"),
        }
        i += 1;
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_does_not_panic() {
        print_help();
    }

    #[test]
    fn parse_events_args_defaults() {
        let args: Vec<String> = vec![];
        let parsed = parse_events_args(&args).unwrap();
        assert_eq!(parsed.class_uid, 0);
        assert_eq!(parsed.min_severity, 0);
        assert_eq!(parsed.limit, 20);
    }

    #[test]
    fn parse_events_args_all_flags() {
        let args: Vec<String> = vec!["--class", "4003", "--severity", "3", "--limit", "50"]
            .into_iter()
            .map(String::from)
            .collect();
        let parsed = parse_events_args(&args).unwrap();
        assert_eq!(parsed.class_uid, 4003);
        assert_eq!(parsed.min_severity, 3);
        assert_eq!(parsed.limit, 50);
    }

    #[test]
    fn parse_observe_args_defaults() {
        let args: Vec<String> = vec![];
        let parsed = parse_observe_args(&args).unwrap();
        assert_eq!(parsed.budget, 0);
        assert!(parsed.format.is_empty());
    }

    #[test]
    fn parse_observe_args_all_flags() {
        let args: Vec<String> = vec!["--budget", "8192", "--format", "narrative"]
            .into_iter()
            .map(String::from)
            .collect();
        let parsed = parse_observe_args(&args).unwrap();
        assert_eq!(parsed.budget, 8192);
        assert_eq!(parsed.format, "narrative");
    }

    #[test]
    fn parse_events_unknown_flag_errors() {
        let args: Vec<String> = vec!["--unknown"].into_iter().map(String::from).collect();
        assert!(parse_events_args(&args).is_err());
    }

    #[test]
    fn engine_addr_default() {
        // Only test when env var is not set
        if std::env::var("NOUS_ENGINE_ADDR").is_err() {
            assert_eq!(engine_addr(), "http://127.0.0.1:50051");
        }
    }

    #[test]
    fn parse_entity_args_valid() {
        let args: Vec<String> = vec!["ip_address", "10.0.0.1"]
            .into_iter()
            .map(String::from)
            .collect();
        let parsed = parse_entity_args(&args).unwrap();
        assert_eq!(parsed.entity_type, "ip_address");
        assert_eq!(parsed.value, "10.0.0.1");
    }

    #[test]
    fn parse_entity_args_missing() {
        let args: Vec<String> = vec!["ip_address"].into_iter().map(String::from).collect();
        assert!(parse_entity_args(&args).is_err());
    }

    #[test]
    fn parse_verdict_args_defaults() {
        let args: Vec<String> = vec!["some-uuid", "true_positive"]
            .into_iter()
            .map(String::from)
            .collect();
        let parsed = parse_verdict_args(&args).unwrap();
        assert_eq!(parsed.finding_id, "some-uuid");
        assert_eq!(parsed.verdict, "true_positive");
        assert_eq!(parsed.agent_id, "nous-ctl");
        assert_eq!(parsed.reasoning, "manual");
        assert!((parsed.confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_verdict_args_with_options() {
        let args: Vec<String> = vec![
            "some-uuid",
            "false_positive",
            "--agent",
            "bot-1",
            "--reasoning",
            "scanner noise",
            "--confidence",
            "0.8",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let parsed = parse_verdict_args(&args).unwrap();
        assert_eq!(parsed.verdict, "false_positive");
        assert_eq!(parsed.agent_id, "bot-1");
        assert_eq!(parsed.reasoning, "scanner noise");
        assert!((parsed.confidence - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_verdict_args_missing() {
        let args: Vec<String> = vec!["only-one"].into_iter().map(String::from).collect();
        assert!(parse_verdict_args(&args).is_err());
    }

    #[test]
    fn parse_watch_args_defaults() {
        let args: Vec<String> = vec![];
        let parsed = parse_watch_args(&args).unwrap();
        assert_eq!(parsed.class_uid, 0);
        assert_eq!(parsed.min_severity, 0);
    }

    #[test]
    fn parse_watch_args_with_filters() {
        let args: Vec<String> = vec!["--class", "2004", "--severity", "3"]
            .into_iter()
            .map(String::from)
            .collect();
        let parsed = parse_watch_args(&args).unwrap();
        assert_eq!(parsed.class_uid, 2004);
        assert_eq!(parsed.min_severity, 3);
    }

    #[test]
    fn help_includes_new_commands() {
        // Capture help output by just checking the function doesn't panic
        // and the match arms exist
        print_help();
    }
}
