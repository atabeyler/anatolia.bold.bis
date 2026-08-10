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
//! - **Shared evidence URL**: candidates that have OSINT evidence items
//!   pointing at the same URL are flagged — two people who otherwise look
//!   different but share a source is a genuine (if weak) resolution
//!   signal.
//! - **Shared entity-graph relation** (item 9 in
//!   `docs/HARDENING_CHECKLIST.md`): candidates that share the same
//!   recorded `alias`, `username`, or `organization` value (see
//!   `db::entity_graph`) — same normalization as name comparison
//!   (lowercased, whitespace-collapsed), compared per relation type so a
//!   shared alias is never conflated with a shared organization.
//!
//! Every match reports exactly *which* signals fired
//! (`PossibleDuplicate::matched_signals`) — never just a single opaque
//! score — so a reviewer can judge a match on its own terms (a name
//! typo is weaker evidence than an identical username, for instance)
//! rather than trusting a blended number.
//!
//! Deliberately not attempted here: cross-referencing national ID (that
//! field is encrypted specifically so it can't be used for fuzzy/plaintext
//! matching — see `national_id.rs`), phonetic matching, or geography/
//! temporal signals (candidates have no location or time-window data of
//! their own to compare — a search's coordinates belong to the search,
//! not durably to a candidate — so there is nothing genuine to compare
//! here without inventing data that doesn't exist).

use std::collections::HashSet;

use crate::db::{CandidateRow, DbBackend};

/// Below this Jaro-Winkler score, two names are not reported as a
/// possible match at all — a conservative floor chosen to keep the
/// default result set small and actionable rather than noisy.
pub const DEFAULT_NAME_SIMILARITY_THRESHOLD: f64 = 0.90;

/// Which signal(s) contributed to a possible-duplicate match — see the
/// module doc comment. Plain string constants (matching this codebase's
/// `roles.rs`/`db::entity_graph::relation_type` style) rather than an
/// enum, so they serialize directly into the API response.
pub mod signal {
    pub const NAME_SIMILARITY: &str = "name_similarity";
    pub const SHARED_EVIDENCE_URL: &str = "shared_evidence_url";
    pub const SHARED_ALIAS: &str = "shared_alias";
    pub const SHARED_USERNAME: &str = "shared_username";
    pub const SHARED_ORGANIZATION: &str = "shared_organization";
}

pub struct PossibleDuplicate {
    pub candidate: CandidateRow,
    pub name_similarity: f64,
    pub shared_evidence_urls: Vec<String>,
    pub matched_signals: Vec<&'static str>,
}

fn normalize(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// The normalized values a candidate has recorded for one entity-graph
/// relation type (`db::entity_graph::relation_type::{ALIAS,USERNAME,ORGANIZATION}`).
async fn relation_values(
    backend: &DbBackend,
    candidate_id: &str,
    relation_type: &str,
) -> Result<HashSet<String>, sqlx::Error> {
    Ok(
        crate::db::list_relations_for_candidate(backend, candidate_id)
            .await?
            .into_iter()
            .filter(|r| r.relation_type == relation_type)
            .map(|r| normalize(&r.value))
            .collect(),
    )
}

/// Finds candidates other than `candidate_id` whose name similarity to it
/// is at or above `threshold`, or that share an evidence URL or an
/// alias/username/organization entity-graph relation with it — highest
/// name similarity first. Read-only, advisory — see module doc comment.
pub async fn find_possible_duplicates(
    backend: &DbBackend,
    candidate_id: &str,
    threshold: f64,
) -> Result<Vec<PossibleDuplicate>, sqlx::Error> {
    let Some(target) = crate::db::load_candidate_by_id(backend, candidate_id).await? else {
        return Ok(Vec::new());
    };
    let target_name = normalize(&target.full_name);

    let all_candidates = crate::db::list_candidates(backend).await?;
    let target_evidence = crate::db::list_evidence_for_candidate(backend, candidate_id).await?;
    let target_urls: HashSet<String> = target_evidence.into_iter().filter_map(|e| e.url).collect();

    let target_aliases =
        relation_values(backend, candidate_id, crate::db::relation_type::ALIAS).await?;
    let target_usernames =
        relation_values(backend, candidate_id, crate::db::relation_type::USERNAME).await?;
    let target_organizations = relation_values(
        backend,
        candidate_id,
        crate::db::relation_type::ORGANIZATION,
    )
    .await?;

    let mut matches = Vec::new();
    for candidate in all_candidates {
        if candidate.id == target.id {
            continue;
        }
        let similarity = strsim::jaro_winkler(&target_name, &normalize(&candidate.full_name));
        let other_evidence = crate::db::list_evidence_for_candidate(backend, &candidate.id).await?;
        let shared_urls: Vec<String> = other_evidence
            .into_iter()
            .filter_map(|e| e.url)
            .filter(|url| target_urls.contains(url))
            .collect();

        let other_aliases =
            relation_values(backend, &candidate.id, crate::db::relation_type::ALIAS).await?;
        let other_usernames =
            relation_values(backend, &candidate.id, crate::db::relation_type::USERNAME).await?;
        let other_organizations = relation_values(
            backend,
            &candidate.id,
            crate::db::relation_type::ORGANIZATION,
        )
        .await?;

        let mut matched_signals = Vec::new();
        if similarity >= threshold {
            matched_signals.push(signal::NAME_SIMILARITY);
        }
        if !shared_urls.is_empty() {
            matched_signals.push(signal::SHARED_EVIDENCE_URL);
        }
        if !target_aliases.is_disjoint(&other_aliases) {
            matched_signals.push(signal::SHARED_ALIAS);
        }
        if !target_usernames.is_disjoint(&other_usernames) {
            matched_signals.push(signal::SHARED_USERNAME);
        }
        if !target_organizations.is_disjoint(&other_organizations) {
            matched_signals.push(signal::SHARED_ORGANIZATION);
        }

        if !matched_signals.is_empty() {
            matches.push(PossibleDuplicate {
                candidate,
                name_similarity: similarity,
                shared_evidence_urls: shared_urls,
                matched_signals,
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
    use super::normalize;

    #[test]
    fn normalize_lowercases_and_collapses_whitespace() {
        assert_eq!(normalize("  Jane   DOE "), "jane doe");
    }

    #[test]
    fn identical_normalized_names_score_one() {
        assert_eq!(
            strsim::jaro_winkler(&normalize("Jane Doe"), &normalize("jane doe")),
            1.0
        );
    }

    #[test]
    fn clearly_different_names_score_low() {
        let score = strsim::jaro_winkler(&normalize("Jane Doe"), &normalize("Mehmet Yilmaz"));
        assert!(score < 0.7, "expected a low score, got {score}");
    }

    #[test]
    fn a_minor_typo_still_scores_above_the_default_threshold() {
        let score =
            strsim::jaro_winkler(&normalize("Jonathan Smith"), &normalize("Jonathon Smith"));
        assert!(
            score >= super::DEFAULT_NAME_SIMILARITY_THRESHOLD,
            "expected a near-match score, got {score}"
        );
    }
}
