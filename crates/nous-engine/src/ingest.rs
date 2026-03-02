//! Ingestion loop: reads lines from input, parses with adapter, updates state.

use std::path::Path;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, info, warn};

use nous_adapters::suricata::SuricataAdapter;
use nous_adapters::Adapter;

use crate::state_store::SharedState;

/// Run the ingestion loop, reading from the configured input source.
///
/// Reads NDJSON lines, parses each through the Suricata adapter,
/// ingests into shared state, and emits to stdout as NDJSON.
pub async fn run_ingestion(input: &str, shared: SharedState) -> Result<()> {
    let adapter = SuricataAdapter::new();

    if input == "-" {
        info!("reading from stdin");
        let stdin = tokio::io::stdin();
        let reader = BufReader::new(stdin);
        process_lines(reader, &adapter, &shared).await
    } else {
        let path = Path::new(input);
        info!(path = %path.display(), "reading from file");
        let file = tokio::fs::File::open(path)
            .await
            .with_context(|| format!("failed to open {}", path.display()))?;
        let reader = BufReader::new(file);
        process_lines(reader, &adapter, &shared).await
    }
}

/// Process lines from any async reader.
async fn process_lines<R>(
    reader: BufReader<R>,
    adapter: &SuricataAdapter,
    shared: &SharedState,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        match adapter.parse_line(&line) {
            Ok(Some(event)) => {
                // Emit as NDJSON to stdout
                if let Ok(json) = serde_json::to_string(&event) {
                    println!("{json}");
                }

                // Ingest into shared state
                let mut store = shared
                    .write()
                    .map_err(|e| anyhow::anyhow!("state lock poisoned: {e}"))?;
                store.ingest(event);
                debug!(count = store.state.event_count(), "event ingested");
            }
            Ok(None) => {
                // Skippable line (empty, comment, etc.)
            }
            Err(e) => {
                warn!(error = %e, "failed to parse line");
            }
        }
    }

    info!("input stream ended");
    Ok(())
}
