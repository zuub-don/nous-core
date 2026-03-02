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
    GetStatusRequest, GetStatusResponse, ObserveRequest, ObserveResponse, QueryEntityRequest,
    QueryEntityResponse, QueryEventsRequest, QueryEventsResponse,
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
}
