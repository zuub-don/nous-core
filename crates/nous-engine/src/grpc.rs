//! gRPC server implementation for NousService.

use std::time::Instant;

use tonic::{Request, Response, Status};

use nous_core::context::{ContextFormat, ContextGenerator, TokenBudget};
use nous_core::entity::EntityType;
use nous_proto::{
    GetStatusRequest, GetStatusResponse, NousService, ObserveRequest, ObserveResponse,
    QueryEntityRequest, QueryEntityResponse, QueryEventsRequest, QueryEventsResponse,
};

use crate::state_store::SharedState;

/// gRPC service implementation backed by shared state.
pub struct NousGrpcService {
    shared: SharedState,
    start_time: Instant,
}

impl NousGrpcService {
    /// Create a new gRPC service backed by the given shared state.
    pub fn new(shared: SharedState) -> Self {
        Self {
            shared,
            start_time: Instant::now(),
        }
    }
}

#[tonic::async_trait]
impl NousService for NousGrpcService {
    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        let store = self
            .shared
            .read()
            .map_err(|e| Status::internal(format!("lock poisoned: {e}")))?;

        Ok(Response::new(GetStatusResponse {
            event_count: store.state.event_count(),
            active_findings: store.state.active_findings(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }

    async fn query_events(
        &self,
        request: Request<QueryEventsRequest>,
    ) -> Result<Response<QueryEventsResponse>, Status> {
        let req = request.into_inner();
        let store = self
            .shared
            .read()
            .map_err(|e| Status::internal(format!("lock poisoned: {e}")))?;

        let class_filter = if req.class_uid == 0 {
            None
        } else {
            Some(req.class_uid)
        };
        let sev_filter = if req.min_severity == 0 {
            None
        } else {
            Some(req.min_severity as u8)
        };
        let limit = if req.limit == 0 {
            100
        } else {
            req.limit as usize
        };

        let events = store.query_events(class_filter, sev_filter, limit);
        let total = events.len() as u64;

        let json_events: Vec<String> = events
            .iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .collect();

        Ok(Response::new(QueryEventsResponse {
            events: json_events,
            total,
        }))
    }

    async fn query_entity(
        &self,
        request: Request<QueryEntityRequest>,
    ) -> Result<Response<QueryEntityResponse>, Status> {
        let req = request.into_inner();
        let store = self
            .shared
            .read()
            .map_err(|e| Status::internal(format!("lock poisoned: {e}")))?;

        let entity_type = match req.entity_type.as_str() {
            "ip_address" => EntityType::IpAddress,
            "domain" => EntityType::Domain,
            "hostname" => EntityType::Hostname,
            "user" => EntityType::User,
            "process" => EntityType::Process,
            "file" => EntityType::File,
            "url" => EntityType::Url,
            other => {
                return Err(Status::invalid_argument(format!(
                    "unknown entity type: {other}"
                )));
            }
        };

        let risk_score = store.state.entity_risk(entity_type, &req.value);

        Ok(Response::new(QueryEntityResponse {
            found: risk_score.is_some(),
            risk_score: risk_score.unwrap_or(0) as u32,
            entity_type: req.entity_type,
            value: req.value,
        }))
    }

    async fn observe(
        &self,
        request: Request<ObserveRequest>,
    ) -> Result<Response<ObserveResponse>, Status> {
        let req = request.into_inner();
        let store = self
            .shared
            .read()
            .map_err(|e| Status::internal(format!("lock poisoned: {e}")))?;

        let budget = match req.token_budget {
            0 => TokenBudget::Medium,
            b if b <= 1024 => TokenBudget::Tiny,
            b if b <= 2048 => TokenBudget::Small,
            b if b <= 4096 => TokenBudget::Medium,
            b if b <= 8192 => TokenBudget::Large,
            _ => TokenBudget::XLarge,
        };

        let format = match req.format.as_str() {
            "narrative" => ContextFormat::Narrative,
            "delta" => ContextFormat::Delta,
            _ => ContextFormat::StructuredJson,
        };

        let generator = ContextGenerator::new(budget, format);
        let window = generator.generate(&store.state);

        let json = serde_json::to_string(&window)
            .map_err(|e| Status::internal(format!("serialization error: {e}")))?;

        Ok(Response::new(ObserveResponse {
            context_window: json,
        }))
    }
}
