//! gRPC server implementation for NousService.

use std::pin::Pin;
use std::sync::Mutex;
use std::time::Instant;

use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

use nous_core::action::{ActionType, AgentAction};
use nous_core::context::{ContextFormat, ContextGenerator, TokenBudget};
use nous_core::entity::EntityType;
use nous_core::verdict::{TriageVerdict, Verdict};
use nous_proto::{
    EventNotification, GetStatusRequest, GetStatusResponse, NousService, ObserveRequest,
    ObserveResponse, QueryEntityRequest, QueryEntityResponse, QueryEventsRequest,
    QueryEventsResponse, StreamEventsRequest, SubmitActionRequest, SubmitActionResponse,
    SubmitVerdictRequest, SubmitVerdictResponse,
};

use crate::bus::EventBus;
use crate::feedback::apply_verdict;
use crate::state_store::SharedState;

/// gRPC service implementation backed by shared state.
pub struct NousGrpcService {
    shared: SharedState,
    start_time: Instant,
    bus: EventBus,
    context_gen: Mutex<ContextGenerator>,
}

impl NousGrpcService {
    /// Create a new gRPC service backed by the given shared state and event bus.
    pub fn new(shared: SharedState, bus: EventBus) -> Self {
        Self {
            shared,
            start_time: Instant::now(),
            bus,
            context_gen: Mutex::new(ContextGenerator::default()),
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

        let entity_type = parse_entity_type(&req.entity_type)?;
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

        let recent: Vec<nous_core::event::NousEvent> =
            store.recent_events_slice(50).into_iter().cloned().collect();

        let view = nous_core::context::StateView {
            state: &store.state,
            recent_events: &recent,
        };

        let mut gen = self
            .context_gen
            .lock()
            .map_err(|e| Status::internal(format!("lock poisoned: {e}")))?;
        *gen = ContextGenerator::new(budget, format);
        let window = gen.generate_from_view(&view);

        let json = serde_json::to_string(&window)
            .map_err(|e| Status::internal(format!("serialization error: {e}")))?;

        Ok(Response::new(ObserveResponse {
            context_window: json,
        }))
    }

    async fn submit_verdict(
        &self,
        request: Request<SubmitVerdictRequest>,
    ) -> Result<Response<SubmitVerdictResponse>, Status> {
        let req = request.into_inner();

        let finding_id: uuid::Uuid = req
            .finding_id
            .parse()
            .map_err(|_| Status::invalid_argument("invalid finding_id UUID"))?;

        let triage = match req.verdict.as_str() {
            "true_positive" => TriageVerdict::TruePositive,
            "false_positive" => TriageVerdict::FalsePositive,
            "benign" => TriageVerdict::Benign,
            "needs_investigation" => TriageVerdict::NeedsInvestigation,
            other => {
                return Err(Status::invalid_argument(format!(
                    "unknown verdict: {other}"
                )));
            }
        };

        let verdict = Verdict::new(
            finding_id,
            triage,
            &req.agent_id,
            &req.reasoning,
            req.confidence,
        );
        let verdict_id = verdict.id.to_string();

        let mut store = self
            .shared
            .write()
            .map_err(|e| Status::internal(format!("lock poisoned: {e}")))?;

        // Apply feedback loop
        apply_verdict(&mut store.state, &verdict, &[]);
        store.store_verdict(verdict);

        Ok(Response::new(SubmitVerdictResponse {
            verdict_id,
            accepted: true,
        }))
    }

    async fn submit_action(
        &self,
        request: Request<SubmitActionRequest>,
    ) -> Result<Response<SubmitActionResponse>, Status> {
        let req = request.into_inner();

        let action_type = match req.action_type.as_str() {
            "escalate" => ActionType::Escalate,
            "suppress" => ActionType::Suppress,
            "isolate" => ActionType::Isolate,
            "block" => ActionType::Block,
            "allowlist" => ActionType::Allowlist,
            other => {
                return Err(Status::invalid_argument(format!(
                    "unknown action type: {other}"
                )));
            }
        };

        let action = AgentAction::new(
            action_type,
            &req.agent_id,
            &req.target_entity_type,
            &req.target_value,
            &req.reasoning,
        );
        let action_id = action.id.to_string();

        tracing::info!(
            action_type = req.action_type,
            target = req.target_value,
            agent = req.agent_id,
            "action submitted"
        );

        Ok(Response::new(SubmitActionResponse {
            action_id,
            accepted: true,
        }))
    }

    type StreamEventsStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<EventNotification, Status>> + Send>>;

    async fn stream_events(
        &self,
        request: Request<StreamEventsRequest>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        let req = request.into_inner();
        let rx = self.bus.subscribe();

        let stream = BroadcastStream::new(rx).filter_map(move |result| {
            match result {
                Ok(event) => {
                    // Apply filters
                    if req.class_uid != 0 && event.class_uid != req.class_uid {
                        return None;
                    }
                    if req.min_severity != 0 && (event.severity.id() as u32) < req.min_severity {
                        return None;
                    }

                    let event_json = serde_json::to_string(&event).unwrap_or_default();
                    Some(Ok(EventNotification {
                        event_json,
                        class_uid: event.class_uid,
                        severity: event.severity.id() as u32,
                    }))
                }
                Err(_) => None,
            }
        });

        Ok(Response::new(Box::pin(stream)))
    }
}

#[allow(clippy::result_large_err)]
fn parse_entity_type(s: &str) -> Result<EntityType, Status> {
    match s {
        "ip_address" => Ok(EntityType::IpAddress),
        "domain" => Ok(EntityType::Domain),
        "hostname" => Ok(EntityType::Hostname),
        "user" => Ok(EntityType::User),
        "process" => Ok(EntityType::Process),
        "file" => Ok(EntityType::File),
        "url" => Ok(EntityType::Url),
        other => Err(Status::invalid_argument(format!(
            "unknown entity type: {other}"
        ))),
    }
}
