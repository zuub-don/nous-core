//! # nous-proto
//!
//! Protobuf/gRPC service definitions for the Nous Core API.
//! Types are auto-generated from `proto/nous.proto`.

/// Generated protobuf types and gRPC service stubs.
pub mod nous {
    tonic::include_proto!("nous");
}

pub use nous::nous_service_client::NousServiceClient;
pub use nous::nous_service_server::{NousService, NousServiceServer};
pub use nous::{
    EntityCoOccurrence, EventNotification, GetStatusRequest, GetStatusResponse, ObserveRequest,
    ObserveResponse, QueryEntityRequest, QueryEntityResponse, QueryEventsRequest,
    QueryEventsResponse, StreamEventsRequest, SubmitActionRequest, SubmitActionResponse,
    SubmitVerdictRequest, SubmitVerdictResponse,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_types_exist() {
        let _req = GetStatusRequest {};
        let _resp = GetStatusResponse {
            event_count: 100,
            active_findings: 5,
            uptime_seconds: 3600,
            version: "0.1.0".into(),
        };
    }

    #[test]
    fn request_response_roundtrip() {
        use prost::Message;

        let req = QueryEventsRequest {
            class_uid: 4003,
            min_severity: 2,
            limit: 50,
        };
        let encoded = req.encode_to_vec();
        let decoded = QueryEventsRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.class_uid, 4003);
        assert_eq!(decoded.min_severity, 2);
        assert_eq!(decoded.limit, 50);
    }

    #[test]
    fn observe_request_defaults() {
        let req = ObserveRequest {
            token_budget: 0,
            format: String::new(),
        };
        assert_eq!(req.token_budget, 0);
        assert!(req.format.is_empty());
    }

    #[test]
    fn entity_co_occurrence_type_exists() {
        let cooc = EntityCoOccurrence {
            entity_type: "domain".into(),
            value: "evil.com".into(),
            count: 23,
        };
        assert_eq!(cooc.count, 23);
    }

    #[test]
    fn query_entity_response_has_new_fields() {
        let resp = QueryEntityResponse {
            found: true,
            risk_score: 75,
            entity_type: "ip_address".into(),
            value: "10.0.0.1".into(),
            hit_count: 47,
            first_seen: 1_000_000,
            last_seen: 2_000_000,
            co_occurrences: vec![EntityCoOccurrence {
                entity_type: "domain".into(),
                value: "evil.com".into(),
                count: 23,
            }],
        };
        assert_eq!(resp.hit_count, 47);
        assert_eq!(resp.co_occurrences.len(), 1);
    }

    #[test]
    fn new_types_instantiate() {
        let _vr = SubmitVerdictRequest {
            finding_id: "uuid".into(),
            verdict: "true_positive".into(),
            agent_id: "agent-1".into(),
            reasoning: "confirmed".into(),
            confidence: 0.95,
        };
        let _ar = SubmitActionRequest {
            action_type: "block".into(),
            agent_id: "agent-1".into(),
            target_entity_type: "ip_address".into(),
            target_value: "10.0.0.1".into(),
            reasoning: "confirmed C2".into(),
        };
        let _sr = StreamEventsRequest {
            class_uid: 0,
            min_severity: 0,
        };
        let _en = EventNotification {
            event_json: "{}".into(),
            class_uid: 4003,
            severity: 1,
        };
    }

    #[test]
    fn verdict_response_roundtrip() {
        use prost::Message;

        let resp = SubmitVerdictResponse {
            verdict_id: "test-id".into(),
            accepted: true,
        };
        let encoded = resp.encode_to_vec();
        let decoded = SubmitVerdictResponse::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.verdict_id, "test-id");
        assert!(decoded.accepted);
    }
}
