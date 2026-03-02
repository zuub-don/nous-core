//! Context window generator: compresses semantic state into token-budgeted
//! situation reports for LLM consumption.

use serde::{Deserialize, Serialize};

use crate::event::NousEvent;
use crate::severity::Severity;
use crate::state::SemanticState;

/// Token budget presets for context window generation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenBudget {
    Tiny = 1024,
    Small = 2048,
    #[default]
    Medium = 4096,
    Large = 8192,
    XLarge = 16384,
}

/// Output format for the context window.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextFormat {
    /// Structured JSON for tool-use agents.
    #[default]
    StructuredJson,
    /// Natural language narrative for chat-based agents.
    Narrative,
    /// Delta report: what changed since last observation.
    Delta,
}

/// A generated context window — the primary output consumed by AI agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextWindow {
    /// When this window was generated (epoch nanos).
    pub generated_at: i64,
    /// Token budget used.
    pub token_budget: usize,
    /// Approximate token count of the content.
    pub estimated_tokens: usize,
    /// The format of the content.
    pub format: ContextFormat,
    /// Summary statistics from semantic state.
    pub summary: ContextSummary,
    /// The format-specific content.
    pub content: ContextContent,
}

/// High-level summary included in every context window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSummary {
    pub total_events: u64,
    pub active_findings: u64,
    pub top_classes: Vec<(u32, u64)>,
    pub severity_histogram: [u64; 6],
    pub entity_count: usize,
}

/// Format-specific content of a context window.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "content_type")]
pub enum ContextContent {
    /// Structured JSON sections for tool-use agents.
    StructuredJson(StructuredJsonContent),
    /// Natural language narrative for chat-based agents.
    Narrative(NarrativeContent),
    /// Delta report showing changes since last observation.
    Delta(DeltaContent),
}

/// Structured JSON context content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredJsonContent {
    /// Findings at High or Critical severity.
    pub critical_findings: Vec<String>,
    /// Top entities by risk score.
    pub top_entities: Vec<EntitySummary>,
    /// Baseline statistics.
    pub baseline: BaselineStats,
}

/// Entity summary for context windows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySummary {
    pub entity_type: String,
    pub value: String,
    pub risk_score: u8,
    pub hit_count: u64,
}

/// Baseline statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStats {
    pub severity_distribution: [u64; 6],
    pub top_classes: Vec<(u32, u64)>,
}

/// Narrative context content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeContent {
    pub text: String,
}

/// Delta context content — changes since last observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaContent {
    pub new_findings: u64,
    pub resolved_findings: u64,
    pub new_entities: usize,
    pub risk_changes: Vec<RiskChange>,
    pub text: String,
}

/// A risk score change for an entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskChange {
    pub entity_type: String,
    pub value: String,
    pub old_score: u8,
    pub new_score: u8,
}

/// View into state + recent events for context generation.
pub struct StateView<'a> {
    /// The current semantic state.
    pub state: &'a SemanticState,
    /// Recent events from the event buffer.
    pub recent_events: &'a [NousEvent],
}

/// Estimate token count from a JSON string using byte-ratio heuristic.
pub fn estimate_tokens(json: &str) -> usize {
    json.len() / 4
}

/// Previous snapshot for delta tracking.
#[derive(Debug, Default, Clone)]
struct PreviousSnapshot {
    active_findings: u64,
    entity_count: usize,
    entity_risks: Vec<(String, String, u8)>, // (type, value, score)
}

/// Generates context windows from semantic state.
#[derive(Debug, Default)]
pub struct ContextGenerator {
    budget: TokenBudget,
    format: ContextFormat,
    previous: Option<PreviousSnapshot>,
}

impl ContextGenerator {
    /// Create a generator with the given budget and format.
    pub fn new(budget: TokenBudget, format: ContextFormat) -> Self {
        Self {
            budget,
            format,
            previous: None,
        }
    }

    /// Generate a context window from the current semantic state.
    pub fn generate(&mut self, state: &SemanticState) -> ContextWindow {
        let view = StateView {
            state,
            recent_events: &[],
        };
        self.generate_from_view(&view)
    }

    /// Generate a context window from a state view with recent events.
    pub fn generate_from_view(&mut self, view: &StateView<'_>) -> ContextWindow {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let state = view.state;

        let summary = ContextSummary {
            total_events: state.event_count(),
            active_findings: state.active_findings(),
            top_classes: state.top_classes(10),
            severity_histogram: *state.severity_histogram(),
            entity_count: state.entity_count(),
        };

        let content = match self.format {
            ContextFormat::StructuredJson => {
                self.generate_structured_json(state, view.recent_events)
            }
            ContextFormat::Narrative => self.generate_narrative(state),
            ContextFormat::Delta => self.generate_delta(state),
        };

        // Estimate tokens from content serialization
        let content_json = serde_json::to_string(&content).unwrap_or_default();
        let summary_json = serde_json::to_string(&summary).unwrap_or_default();
        let estimated_tokens = estimate_tokens(&content_json) + estimate_tokens(&summary_json) + 32;
        let budget_val = self.budget as usize;
        let estimated_tokens = estimated_tokens.min(budget_val);

        // Update snapshot for delta tracking
        self.previous = Some(PreviousSnapshot {
            active_findings: state.active_findings(),
            entity_count: state.entity_count(),
            entity_risks: state
                .top_entities(50)
                .into_iter()
                .map(|((et, val), meta)| {
                    (
                        format!("{et:?}").to_lowercase(),
                        val.clone(),
                        meta.risk_score,
                    )
                })
                .collect(),
        });

        ContextWindow {
            generated_at: now,
            token_budget: budget_val,
            estimated_tokens,
            format: self.format,
            summary,
            content,
        }
    }

    fn generate_structured_json(
        &self,
        state: &SemanticState,
        recent_events: &[NousEvent],
    ) -> ContextContent {
        // Collect critical findings from recent events
        let critical_findings: Vec<String> = recent_events
            .iter()
            .filter(|e| e.severity >= Severity::High && e.class_uid == 2004)
            .filter_map(|e| {
                if let crate::event::EventPayload::DetectionFinding(f) = &e.payload {
                    Some(format!("[{}] {}", e.severity.label(), f.title))
                } else {
                    None
                }
            })
            .collect();

        let top_entities: Vec<EntitySummary> = state
            .top_entities(10)
            .into_iter()
            .map(|((et, val), meta)| EntitySummary {
                entity_type: format!("{et:?}").to_lowercase(),
                value: val.clone(),
                risk_score: meta.risk_score,
                hit_count: meta.hit_count,
            })
            .collect();

        ContextContent::StructuredJson(StructuredJsonContent {
            critical_findings,
            top_entities,
            baseline: BaselineStats {
                severity_distribution: *state.severity_histogram(),
                top_classes: state.top_classes(10),
            },
        })
    }

    fn generate_narrative(&self, state: &SemanticState) -> ContextContent {
        let hist = state.severity_histogram();
        let top = state.top_entities(3);
        let top_threat = top
            .first()
            .map(|((et, val), meta)| format!("{val} ({et:?}, risk {})", meta.risk_score));

        let text = format!(
            "Security situation as of now: {} events ingested, {} active findings. \
             Severity breakdown: {} critical, {} high, {} medium, {} low, {} info. \
             {} entities tracked.{}",
            state.event_count(),
            state.active_findings(),
            hist[5],
            hist[4],
            hist[3],
            hist[2],
            hist[1],
            state.entity_count(),
            top_threat
                .map(|t| format!(" Top threat: {t}."))
                .unwrap_or_default(),
        );

        ContextContent::Narrative(NarrativeContent { text })
    }

    fn generate_delta(&mut self, state: &SemanticState) -> ContextContent {
        let prev = self.previous.take().unwrap_or_default();

        let new_findings = state.active_findings().saturating_sub(prev.active_findings);
        let resolved_findings = prev.active_findings.saturating_sub(state.active_findings());
        let new_entities = state.entity_count().saturating_sub(prev.entity_count);

        // Compute risk changes
        let current_risks: Vec<(String, String, u8)> = state
            .top_entities(50)
            .into_iter()
            .map(|((et, val), meta)| {
                (
                    format!("{et:?}").to_lowercase(),
                    val.clone(),
                    meta.risk_score,
                )
            })
            .collect();

        let risk_changes: Vec<RiskChange> = current_risks
            .iter()
            .filter_map(|(et, val, score)| {
                prev.entity_risks
                    .iter()
                    .find(|(pet, pval, _)| pet == et && pval == val)
                    .and_then(|(_, _, old_score)| {
                        if old_score != score {
                            Some(RiskChange {
                                entity_type: et.clone(),
                                value: val.clone(),
                                old_score: *old_score,
                                new_score: *score,
                            })
                        } else {
                            None
                        }
                    })
            })
            .collect();

        let text = format!(
            "Delta: {} new findings, {} resolved, {} new entities, {} risk changes.",
            new_findings,
            resolved_findings,
            new_entities,
            risk_changes.len()
        );

        ContextContent::Delta(DeltaContent {
            new_findings,
            resolved_findings,
            new_entities,
            risk_changes,
            text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::EntityType;
    use crate::event::*;
    use crate::severity::Severity;
    use crate::state::SemanticState;

    fn make_state_with_events() -> SemanticState {
        let mut state = SemanticState::new();
        let evt = NousEvent::new(
            1_000_000_000,
            4003,
            4,
            Severity::Info,
            EventSource {
                adapter: AdapterType::Suricata,
                product: None,
                sensor: None,
                original_id: None,
            },
            EventPayload::SystemLog(SystemLog {
                source_name: "test".into(),
                message: "test".into(),
            }),
        );
        state.ingest(&evt);
        state.ingest(&evt);
        state.add_finding();
        state.update_entity_risk(EntityType::IpAddress, "10.0.0.1", 80);
        state
    }

    #[test]
    fn context_generator_defaults() {
        let mut gen = ContextGenerator::default();
        let state = SemanticState::new();
        let window = gen.generate(&state);

        assert_eq!(window.token_budget, 4096);
        assert_eq!(window.format, ContextFormat::StructuredJson);
        assert_eq!(window.summary.total_events, 0);
    }

    #[test]
    fn context_window_reflects_state() {
        let mut gen = ContextGenerator::new(TokenBudget::Small, ContextFormat::Narrative);
        let state = make_state_with_events();

        let window = gen.generate(&state);
        assert_eq!(window.summary.total_events, 2);
        assert_eq!(window.summary.active_findings, 1);
        assert_eq!(window.token_budget, 2048);
        assert_eq!(window.format, ContextFormat::Narrative);
    }

    #[test]
    fn context_window_serde_roundtrip() {
        let mut gen = ContextGenerator::default();
        let state = SemanticState::new();
        let window = gen.generate(&state);

        let json = serde_json::to_string(&window).unwrap();
        let deser: ContextWindow = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.token_budget, window.token_budget);
    }

    #[test]
    fn structured_json_has_entities() {
        let mut gen = ContextGenerator::new(TokenBudget::Medium, ContextFormat::StructuredJson);
        let state = make_state_with_events();
        let window = gen.generate(&state);

        match &window.content {
            ContextContent::StructuredJson(sj) => {
                assert!(!sj.top_entities.is_empty());
                assert_eq!(sj.top_entities[0].risk_score, 80);
            }
            _ => panic!("expected StructuredJson"),
        }
    }

    #[test]
    fn narrative_produces_text() {
        let mut gen = ContextGenerator::new(TokenBudget::Medium, ContextFormat::Narrative);
        let state = make_state_with_events();
        let window = gen.generate(&state);

        match &window.content {
            ContextContent::Narrative(n) => {
                assert!(n.text.contains("2 events"));
                assert!(n.text.contains("1 active findings"));
            }
            _ => panic!("expected Narrative"),
        }
    }

    #[test]
    fn delta_first_call_then_changes() {
        let mut gen = ContextGenerator::new(TokenBudget::Medium, ContextFormat::Delta);
        let mut state = make_state_with_events();

        // First call: everything is "new"
        let w1 = gen.generate(&state);
        match &w1.content {
            ContextContent::Delta(d) => {
                assert!(d.text.contains("Delta"));
            }
            _ => panic!("expected Delta"),
        }

        // Add more findings and generate again
        state.add_finding();
        state.add_finding();
        let w2 = gen.generate(&state);
        match &w2.content {
            ContextContent::Delta(d) => {
                assert_eq!(d.new_findings, 2);
            }
            _ => panic!("expected Delta"),
        }
    }

    #[test]
    fn token_estimation() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("abcd"), 1);
        assert_eq!(estimate_tokens("abcdefgh"), 2);
        // Typical JSON
        let json = serde_json::json!({"key": "value", "count": 42}).to_string();
        assert!(estimate_tokens(&json) > 0);
    }

    #[test]
    fn top_classes_populated() {
        let mut gen = ContextGenerator::new(TokenBudget::Medium, ContextFormat::StructuredJson);
        let state = make_state_with_events();
        let window = gen.generate(&state);
        assert!(!window.summary.top_classes.is_empty());
    }

    #[test]
    fn summary_has_severity_histogram_and_entity_count() {
        let mut gen = ContextGenerator::default();
        let state = make_state_with_events();
        let window = gen.generate(&state);
        assert_eq!(window.summary.severity_histogram[1], 2); // 2 Info events
        assert!(window.summary.entity_count > 0);
    }

    #[test]
    fn context_content_serde_roundtrip() {
        let content = ContextContent::Narrative(NarrativeContent {
            text: "test narrative".into(),
        });
        let json = serde_json::to_string(&content).unwrap();
        let deser: ContextContent = serde_json::from_str(&json).unwrap();
        match deser {
            ContextContent::Narrative(n) => assert_eq!(n.text, "test narrative"),
            _ => panic!("expected Narrative"),
        }
    }
}
