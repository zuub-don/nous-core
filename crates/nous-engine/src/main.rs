//! nous-engine: headless daemon for event ingestion, state management, and gRPC API.

mod bus;
mod config;
mod consumers;
mod correlation;
mod feedback;
mod grpc;
mod ingest;
#[cfg(feature = "persistence")]
mod persistence;
mod state_store;

use anyhow::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::bus::EventBus;
use crate::config::Config;
use crate::grpc::NousGrpcService;
use crate::state_store::new_shared_state;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("nous=info".parse()?))
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = Config::from_args(&args).map_err(|e| anyhow::anyhow!(e))?;

    info!(
        input = %config.input,
        grpc_port = config.grpc_port,
        buffer_size = config.buffer_size,
        adapter = %config.adapter,
        correlation_window = config.correlation_window_secs,
        "nous-engine v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    let shared = new_shared_state(config.buffer_size);
    let bus = EventBus::new(config.buffer_size);

    // Spawn state consumer
    let state_shared = shared.clone();
    let state_bus = bus.clone();
    tokio::spawn(async move {
        consumers::state_consumer(&state_bus, state_shared).await;
    });

    // Spawn NDJSON emitter
    let ndjson_bus = bus.clone();
    tokio::spawn(async move {
        consumers::ndjson_emitter(&ndjson_bus).await;
    });

    // Spawn correlation consumer
    let corr_bus = bus.clone();
    let corr_window = config.correlation_window_secs;
    tokio::spawn(async move {
        consumers::correlation_consumer(&corr_bus, corr_window).await;
    });

    // Optionally spawn persistence consumer
    #[cfg(feature = "persistence")]
    if let Some(db_url) = &config.db_url {
        let pool = sqlx::PgPool::connect(db_url)
            .await
            .map_err(|e| anyhow::anyhow!("failed to connect to database: {e}"))?;
        persistence::init_db(&pool).await?;
        let persist_bus = bus.clone();
        tokio::spawn(async move {
            consumers::persistence_consumer(&persist_bus, pool).await;
        });
        info!("persistence consumer started");
    }

    // Spawn gRPC server
    let grpc_shared = shared.clone();
    let grpc_bus = bus.clone();
    let grpc_addr = format!("0.0.0.0:{}", config.grpc_port).parse()?;
    let grpc_handle = tokio::spawn(async move {
        info!(addr = %grpc_addr, "gRPC server starting");
        tonic::transport::Server::builder()
            .add_service(nous_proto::NousServiceServer::new(NousGrpcService::new(
                grpc_shared,
                grpc_bus,
            )))
            .serve(grpc_addr)
            .await
    });

    // Run ingestion loop (blocks until input ends)
    let ingest_result = ingest::run_ingestion(&config.input, &config.adapter, bus).await;

    if let Err(e) = &ingest_result {
        tracing::error!(error = %e, "ingestion error");
    }

    // If ingestion ends (e.g., file EOF), abort the gRPC server
    grpc_handle.abort();

    info!("nous-engine shutting down");
    ingest_result?;
    Ok(())
}
