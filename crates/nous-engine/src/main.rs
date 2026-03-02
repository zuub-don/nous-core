//! nous-engine: headless daemon for event ingestion, state management, and gRPC API.

mod config;
mod grpc;
mod ingest;
mod state_store;

use anyhow::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;

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
        "nous-engine v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    let shared = new_shared_state(config.buffer_size);

    // Spawn gRPC server
    let grpc_shared = shared.clone();
    let grpc_addr = format!("0.0.0.0:{}", config.grpc_port).parse()?;
    let grpc_handle = tokio::spawn(async move {
        info!(addr = %grpc_addr, "gRPC server starting");
        tonic::transport::Server::builder()
            .add_service(nous_proto::NousServiceServer::new(NousGrpcService::new(
                grpc_shared,
            )))
            .serve(grpc_addr)
            .await
    });

    // Run ingestion loop (blocks until input ends)
    let ingest_result = ingest::run_ingestion(&config.input, shared).await;

    if let Err(e) = &ingest_result {
        tracing::error!(error = %e, "ingestion error");
    }

    // If ingestion ends (e.g., file EOF), abort the gRPC server
    grpc_handle.abort();

    info!("nous-engine shutting down");
    ingest_result?;
    Ok(())
}
