use anyhow::Result;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("nous=info".parse()?))
        .json()
        .init();

    tracing::info!("nous-engine starting");

    // TODO: Parse CLI args, load config, start ingestion pipeline
    // Placeholder: print version and exit cleanly
    println!("nous-engine v{}", env!("CARGO_PKG_VERSION"));

    Ok(())
}
