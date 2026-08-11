//! Builds an external-provider query string from a candidate's identity,
//! for the automatic biometric-search → OSINT trigger (see
//! `search::run_queued_search`). Deliberately conservative: a candidate's
//! full name is the only field this ever sends to a third-party
//! search/news API. Everything else `CandidateRow`/`SearchCandidateRow`
//! carry — reference code, internal id, notes, organization — either
//! isn't an identity string at all or can hold internal/sensitive
//! investigation context, so callers only ever pass this function the
//! one field known to be safe, never a whole candidate record it could
//! be tempted to pull more out of.

/// Returns the query to send to web/news OSINT providers for a candidate
/// with this `full_name`, or `None` if there is no usable identity string
/// (empty/whitespace) — callers must skip evidence collection entirely in
/// that case rather than querying with an empty or placeholder string.
pub fn build_query(full_name: &str) -> Option<String> {
    let name = full_name.trim();
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_the_trimmed_full_name() {
        assert_eq!(
            build_query("  Ahmet Yilmaz  "),
            Some("Ahmet Yilmaz".to_string())
        );
    }

    #[test]
    fn empty_full_name_yields_no_query() {
        assert_eq!(build_query("   "), None);
    }
}
