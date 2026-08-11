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

        // Google Vision can fall back to generic best-guess labels such as
        // "screenshot" when it has no meaningful matching-page context. Never
        // fan those labels out into Tavily/Currents: doing so creates a large
        // amount of unrelated screenshot/tutorial noise.
        if lower.starts_with("best guess:") {
            let guess = lower.trim_start_matches("best guess:").trim();
            return matches!(
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
            );
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
        )
    }

    fn usable(value: &str) -> Option<String> {
        let value = value.trim();
        if value.len() < 3 || is_generic_visual_context(value) {
            return None;
        }
        Some(value.chars().take(180).collect())
    }

    // If Vision explicitly says its best guess is only a generic visual label,
    // do not use the accompanying generic tutorial/page title either. This
    // prevents a "best guess: screenshot" response from turning into searches
    // for screenshot tutorials.
    if snippet.is_some_and(is_generic_visual_context) {
        return None;
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
    fn reverse_context_rejects_generic_face_best_guess() {
        assert_eq!(
            build_reverse_context_query("Generic portrait page", Some("best guess: face")),
            None
        );
    }
}
