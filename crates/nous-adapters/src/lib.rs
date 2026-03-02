//! # nous-adapters
//!
//! Ingestion adapters: convert external security telemetry formats
//! into normalized Nous Core events.

use nous_core::error::Result;
use nous_core::event::NousEvent;

pub mod suricata;

/// Trait implemented by all ingestion adapters.
pub trait Adapter {
    /// Human-readable adapter name (e.g., "suricata").
    fn name(&self) -> &'static str;

    /// Parse a single input line into a NousEvent.
    ///
    /// Returns `Ok(None)` for lines that should be skipped (comments, empty).
    /// Returns `Ok(Some(event))` for successfully parsed events.
    /// Returns `Err` for malformed input that should be reported.
    fn parse_line(&self, line: &str) -> Result<Option<NousEvent>>;
}
