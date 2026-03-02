//! Ingestion loop: reads lines from input, parses with adapter, publishes to bus.

use std::path::Path;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, info, warn};

use nous_adapters::journald::JournaldAdapter;
use nous_adapters::suricata::SuricataAdapter;
use nous_adapters::syslog_adapter::SyslogAdapter;
use nous_adapters::zeek::ZeekAdapter;
use nous_adapters::Adapter;

use crate::bus::EventBus;

/// Select an adapter by name.
pub fn select_adapter(name: &str) -> Box<dyn Adapter> {
    match name {
        "suricata" => Box::new(SuricataAdapter::new()),
        "zeek" => Box::new(ZeekAdapter::new()),
        "syslog" => Box::new(SyslogAdapter::new()),
        "journald" => Box::new(JournaldAdapter::new()),
        _ => Box::new(SuricataAdapter::new()), // "auto" defaults to suricata
    }
}

/// Run the ingestion loop, reading from the configured input source.
///
/// Reads NDJSON lines, parses each through the selected adapter,
/// and publishes to the event bus.
pub async fn run_ingestion(input: &str, adapter_name: &str, bus: EventBus) -> Result<()> {
    let adapter = select_adapter(adapter_name);

    if input == "-" {
        info!(adapter = adapter.name(), "reading from stdin");
        let stdin = tokio::io::stdin();
        let reader = BufReader::new(stdin);
        process_lines(reader, adapter.as_ref(), &bus).await
    } else {
        let path = Path::new(input);
        info!(path = %path.display(), adapter = adapter.name(), "reading from file");
        let file = tokio::fs::File::open(path)
            .await
            .with_context(|| format!("failed to open {}", path.display()))?;
        let reader = BufReader::new(file);
        process_lines(reader, adapter.as_ref(), &bus).await
    }
}

/// Process lines from any async reader.
async fn process_lines<R>(reader: BufReader<R>, adapter: &dyn Adapter, bus: &EventBus) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = reader.lines();
    let mut count = 0u64;

    while let Some(line) = lines.next_line().await? {
        match adapter.parse_line(&line) {
            Ok(Some(mut event)) => {
                // Set raw line for audit trail
                event.raw = Some(line);

                // Publish to event bus
                bus.publish(event);
                count += 1;
                debug!(count, "event published to bus");
            }
            Ok(None) => {
                // Skippable line (empty, comment, etc.)
            }
            Err(e) => {
                warn!(error = %e, "failed to parse line");
            }
        }
    }

    info!(total = count, "input stream ended");
    Ok(())
}
