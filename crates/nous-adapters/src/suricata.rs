//! Suricata EVE JSON adapter.
//!
//! Converts Suricata EVE JSON events into normalized Nous Core events.

use nous_core::error::{NousError, Result};
use nous_core::event::NousEvent;

/// Parse a single Suricata EVE JSON line into a NousEvent.
///
/// # Errors
///
/// Returns `NousError::Normalization` if the JSON is malformed or
/// contains an unsupported event type.
pub fn parse_eve_line(_line: &str) -> Result<NousEvent> {
    // TODO: Implement full EVE JSON parsing
    Err(NousError::Normalization(
        "suricata adapter not yet implemented".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_eve_line_returns_error_for_unimplemented() {
        let result = parse_eve_line("{}");
        assert!(result.is_err());
    }
}
