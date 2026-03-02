//! Context window generator: compresses semantic state into token-budgeted
//! situation reports for LLM consumption.

use serde::{Deserialize, Serialize};

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
}

/// High-level summary included in every context window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSummary {
    pub total_events: u64,
    pub active_findings: u64,
    pub top_classes: Vec<(u32, u64)>,
}

/// Generates context windows from semantic state.
#[derive(Debug, Default)]
pub struct ContextGenerator {
    budget: TokenBudget,
    format: ContextFormat,
}

impl ContextGenerator {
    /// Create a generator with the given budget and format.
    pub fn new(budget: TokenBudget, format: ContextFormat) -> Self {
        Self { budget, format }
    }

    /// Generate a context window from the current semantic state.
    pub fn generate(&self, state: &SemanticState) -> ContextWindow {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let summary = ContextSummary {
            total_events: state.event_count(),
            active_findings: state.active_findings(),
            top_classes: Vec::new(),
        };

        // Estimated tokens is a rough approximation; real implementation
        // will use a tokenizer or byte-ratio heuristic.
        let estimated_tokens = 64 + (state.event_count() as usize).min(self.budget as usize);

        ContextWindow {
            generated_at: now,
            token_budget: self.budget as usize,
            estimated_tokens,
            format: self.format,
            summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::*;
    use crate::severity::Severity;
    use crate::state::SemanticState;

    #[test]
    fn context_generator_defaults() {
        let gen = ContextGenerator::default();
        let state = SemanticState::new();
        let window = gen.generate(&state);

        assert_eq!(window.token_budget, 4096);
        assert_eq!(window.format, ContextFormat::StructuredJson);
        assert_eq!(window.summary.total_events, 0);
    }

    #[test]
    fn context_window_reflects_state() {
        let gen = ContextGenerator::new(TokenBudget::Small, ContextFormat::Narrative);
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

        let window = gen.generate(&state);
        assert_eq!(window.summary.total_events, 2);
        assert_eq!(window.summary.active_findings, 1);
        assert_eq!(window.token_budget, 2048);
        assert_eq!(window.format, ContextFormat::Narrative);
    }

    #[test]
    fn context_window_serde_roundtrip() {
        let gen = ContextGenerator::default();
        let state = SemanticState::new();
        let window = gen.generate(&state);

        let json = serde_json::to_string(&window).unwrap();
        let deser: ContextWindow = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.token_budget, window.token_budget);
    }
}
