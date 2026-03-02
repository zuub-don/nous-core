//! nous-ctl: CLI client for querying the Nous Core engine.

use anyhow::{Context, Result};

use nous_proto::{GetStatusRequest, NousServiceClient, ObserveRequest, QueryEventsRequest};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let subcommand = args.first().map(|s| s.as_str()).unwrap_or("help");

    match subcommand {
        "status" => cmd_status().await,
        "events" => cmd_events(&args[1..]).await,
        "observe" => cmd_observe(&args[1..]).await,
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
}
