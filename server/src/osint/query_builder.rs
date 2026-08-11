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
///
/// A page title is allowed to fan out into Tavily/Currents only when the
/// reverse-image provider explicitly reported a full or partial image match.
/// Generic best-guess labels and visually-similar-only results are deliberately
/// rejected because they create unrelated topic searches.
pub fn build_reverse_context_query(title: &str, snippet: Option<&str>) -> Option<String> {
    fn normalized(value: &str) -> String {
        value
            .trim()
            .to_ascii_lowercase()
            .replace(['\n', '\r', '\t'], " ")
    }

    fn is_generic_visual_context(value: &str) -> bool {
        let lower = normalized(value);
        if lower.is_empty() {
            return true;
        }

        let generic = |guess: &str| {
            matches!(
                guess,
                "screenshot"
                    | "screen shot"
                    | "screen capture"
                    | "photo"
                    | "image"
                    | "picture"
                    | "person"
                    | "people"
                    | "man"
                    | "woman"
                    | "face"
                    | "selfie"
                    | "gentleman"
                    | "lady"
                    | "portrait"
            )
        };

        if lower.starts_with("best guess:") {
            return generic(lower.trim_start_matches("best guess:").trim());
        }

        matches!(
            lower.as_str(),
            "full matching image"
                | "partial matching image"
                | "visually similar image"
                | "web page containing a matching image"
                | "screenshot"
                | "screen shot"
                | "screen capture"
                | "photo"
                | "image"
                | "picture"
                | "person"
                | "people"
                | "man"
                | "woman"
                | "face"
                | "selfie"
                | "gentleman"
                | "lady"
                | "portrait"
        )
    }

    fn has_explicit_image_match(value: &str) -> bool {
        let lower = normalized(value);
        lower.contains("full image match") || lower.contains("partial image match")
    }

    fn usable(value: &str) -> Option<String> {
        let value = value.trim();
        if value.len() < 3 || is_generic_visual_context(value) {
            return None;
        }
        Some(value.chars().take(180).collect())
    }

    let snippet = snippet?;

    // Do not turn a generic Vision label (for example "best guess:
    // gentleman") or a visually-similar-only result into a text search.
    // Only explicit full/partial image matches provide enough evidence to use
    // the public page title as an enrichment seed.
    if !has_explicit_image_match(snippet) {
        return None;
    }

    usable(title)
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
    fn reverse_context_uses_title_for_explicit_partial_match() {
        assert_eq!(
            build_reverse_context_query(
                " Example news page ",
                Some("1 partial image match(es) · best guess: gentleman")
            ),
            Some("Example news page".to_string())
        );
    }

    #[test]
    fn reverse_context_rejects_visually_similar_only_result() {
        assert_eq!(
            build_reverse_context_query("Visually similar image", Some("selfie")),
            None
        );
    }

    #[test]
    fn reverse_context_rejects_generic_screenshot_best_guess() {
        assert_eq!(
            build_reverse_context_query(
                "How to Take a Screenshot on Windows",
                Some("best guess: screenshot")
            ),
            None
        );
    }

    #[test]
    fn reverse_context_rejects_generic_gentleman_best_guess() {
        assert_eq!(
            build_reverse_context_query("WHAT IS A GENTLEMAN?", Some("best guess: gentleman")),
            None
        );
    }

    #[test]
    fn reverse_context_keeps_real_partial_match_despite_generic_guess() {
        assert_eq!(
            build_reverse_context_query(
                "Sedat Peker'in örgütü",
                Some("1 partial image match(es) · best guess: gentleman")
            ),
            Some("Sedat Peker'in örgütü".to_string())
        );
    }
}
