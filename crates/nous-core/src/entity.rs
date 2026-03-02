use serde::{Deserialize, Serialize};

/// A security-relevant entity tracked across events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entity {
    pub entity_type: EntityType,
    pub value: String,
    pub enrichment: Option<Enrichment>,
    pub risk_score: Option<u8>,
}

impl Entity {
    /// Create a new entity with no enrichment or risk score.
    pub fn new(entity_type: EntityType, value: impl Into<String>) -> Self {
        Self {
            entity_type,
            value: value.into(),
            enrichment: None,
            risk_score: None,
        }
    }
}

/// Entity type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    IpAddress,
    Domain,
    Hostname,
    User,
    Process,
    File,
    Url,
}

/// Enrichment data populated by the enricher subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrichment {
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
    pub tags: Vec<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub hit_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_new_defaults() {
        let e = Entity::new(EntityType::Domain, "example.com");
        assert_eq!(e.entity_type, EntityType::Domain);
        assert_eq!(e.value, "example.com");
        assert!(e.enrichment.is_none());
        assert!(e.risk_score.is_none());
    }

    #[test]
    fn entity_serde_roundtrip() {
        let e = Entity {
            entity_type: EntityType::IpAddress,
            value: "192.168.1.1".into(),
            enrichment: Some(Enrichment {
                country: Some("US".into()),
                asn: Some(15169),
                org: Some("Google LLC".into()),
                tags: vec!["cdn".into()],
                first_seen: 1_000_000,
                last_seen: 2_000_000,
                hit_count: 42,
            }),
            risk_score: Some(15),
        };
        let json = serde_json::to_string(&e).unwrap();
        let deser: Entity = serde_json::from_str(&json).unwrap();
        assert_eq!(e, deser);
    }
}
