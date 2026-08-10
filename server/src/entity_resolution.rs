//! Conservative entity resolution over non-biometric signals: given a
//! candidate, finds *other* candidate records that might describe the
//! same real-world person, so a human reviewer can decide whether to
//! merge, link, or dismiss them. This never merges or auto-links
//! anything itself — same "candidates, not verdicts" principle as
//! biometric scores and OSINT evidence confidence: a similarity score is
//! a prompt for human review, never an automated identity decision.
//!
//! Signals used, both real and working (not placeholders):
//! - **Name similarity**: Jaro-Winkler distance (`strsim`) over
//!   normalized (lowercased, whitespace-collapsed) full names — a
//!   standard, well-understood string-similarity metric for name
//!   matching, not a novel or unverified heuristic.
//! - **Shared evidence**: candidates that have OSINT evidence items
//!   pointing at the same URL are flagged — two people who otherwise look
//!   different but share a source is a genuine (if weak) resolution
//!   signal.
//!
//! Deliberately not attempted here: cross-referencing national ID (that
//! field is encrypted specifically so it can't be used for fuzzy/plaintext
//! matching — see `national_id.rs`), phonetic matching, or a persisted
//! entity graph — each is real, separate work, not something to fake with
//! an unreliable heuristic.

use std::collections::HashSet;

use crate::db::{CandidateRow, DbBackend};

/// Below this Jaro-Winkler score, two names are not reported as a
/// possible match at all — a conservative floor chosen to keep the
/// default result set small and actionable rather than noisy.
pub const DEFAULT_NAME_SIMILARITY_THRESHOLD: f64 = 0.90;

pub struct PossibleDuplicate {
    pub candidate: CandidateRow,
    pub name_similarity: f64,
    pub shared_evidence_urls: Vec<String>,
}

fn normalize_name(name: &str) -> String {
    name.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Finds candidates other than `candidate_id` whose name similarity to it
/// is at or above `threshold`, highest similarity first. Read-only,
/// advisory — see module doc comment.
pub async fn find_possible_duplicates(
    backend: &DbBackend,
    candidate_id: &str,
    threshold: f64,
) -> Result<Vec<PossibleDuplicate>, sqlx::Error> {
    let Some(target) = crate::db::load_candidate_by_id(backend, candidate_id).await? else {
        return Ok(Vec::new());
    };
    let target_name = normalize_name(&target.full_name);

    let all_candidates = crate::db::list_candidates(backend).await?;
    let target_evidence = crate::db::list_evidence_for_candidate(backend, candidate_id).await?;
    let target_urls: HashSet<String> = target_evidence.into_iter().filter_map(|e| e.url).collect();

    let mut matches = Vec::new();
    for candidate in all_candidates {
        if candidate.id == target.id {
            continue;
        }
        let similarity = strsim::jaro_winkler(&target_name, &normalize_name(&candidate.full_name));
        let other_evidence = crate::db::list_evidence_for_candidate(backend, &candidate.id).await?;
        let shared_urls: Vec<String> = other_evidence
            .into_iter()
            .filter_map(|e| e.url)
            .filter(|url| target_urls.contains(url))
            .collect();

        if similarity >= threshold || !shared_urls.is_empty() {
            matches.push(PossibleDuplicate {
                candidate,
                name_similarity: similarity,
                shared_evidence_urls: shared_urls,
            });
        }
    }

    matches.sort_by(|a, b| {
        b.name_similarity
            .partial_cmp(&a.name_similarity)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::normalize_name;

    #[test]
    fn normalize_name_lowercases_and_collapses_whitespace() {
        assert_eq!(normalize_name("  Jane   DOE "), "jane doe");
    }

    #[test]
    fn identical_normalized_names_score_one() {
        assert_eq!(
            strsim::jaro_winkler(&normalize_name("Jane Doe"), &normalize_name("jane doe")),
            1.0
        );
    }

    #[test]
    fn clearly_different_names_score_low() {
        let score = strsim::jaro_winkler(
            &normalize_name("Jane Doe"),
            &normalize_name("Mehmet Yilmaz"),
        );
        assert!(score < 0.7, "expected a low score, got {score}");
    }

    #[test]
    fn a_minor_typo_still_scores_above_the_default_threshold() {
        let score = strsim::jaro_winkler(
            &normalize_name("Jonathan Smith"),
            &normalize_name("Jonathon Smith"),
        );
        assert!(
            score >= super::DEFAULT_NAME_SIMILARITY_THRESHOLD,
            "expected a near-match score, got {score}"
        );
    }
}
