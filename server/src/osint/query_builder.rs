//! Builds conservative external-provider query strings for OSINT enrichment.
//! Candidate queries use only the candidate's full name. Reverse-image
//! discovery queries use only public context already returned by the reverse
//! image provider; internal case fields are never sent to third parties.

/// Returns the query to send to web/news OSINT providers for a candidate
/// with this `full_name`, or `None` if there is no usable identity string.
pub fn build_query(full_name: &str) -> Option<String> {
    let name = full_name.trim();
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

/// Builds a text-search seed from public reverse-image evidence. This is used
/// only when the internal biometric repository produced no candidate. It never
/// uses case reference, purpose, operator location, internal ids, or notes.
/// Generic image-only labels are skipped because they carry no searchable web
/// context; a provider-returned page title is preferred, with a short snippet
/// as fallback.
pub fn build_reverse_context_query(title: &str, snippet: Option<&str>) -> Option<String> {
    fn usable(value: &str) -> Option<String> {
        let value = value.trim();
        if value.len() < 3 {
            return None;
        }
        let lower = value.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "full matching image"
                | "partial matching image"
                | "visually similar image"
                | "web page containing a matching image"
        ) {
            return None;
        }
        Some(value.chars().take(180).collect())
    }

    usable(title).or_else(|| snippet.and_then(usable))
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

    #[test]
    fn reverse_context_prefers_public_page_title() {
        assert_eq!(
            build_reverse_context_query(" Example news page ", Some("fallback")),
            Some("Example news page".to_string())
        );
    }

    #[test]
    fn reverse_context_skips_generic_image_labels() {
        assert_eq!(
            build_reverse_context_query("Full matching image", Some("Public page context")),
            Some("Public page context".to_string())
        );
    }
}
