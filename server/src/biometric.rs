//! `BiometricProvider` abstraction (see CLAUDE.md's architecture notes).
//! `MockBiometricProvider` is the only implementation today, so the full
//! search workflow is developable and testable without a real model; a
//! production provider (ONNX Runtime via `ort`, server-side) is added
//! later behind the same trait — callers never need to change.

use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::db::CandidateRow;

pub struct ScoredCandidate {
    pub candidate: CandidateRow,
    pub score: f64,
}

pub trait BiometricProvider: Send + Sync {
    /// Ranks every given candidate against the probe image bytes,
    /// highest similarity first, capped at `top_k`.
    fn search(&self, probe: &[u8], candidates: Vec<CandidateRow>, top_k: usize) -> Vec<ScoredCandidate>;
}

/// Deterministic, content-seeded mock: the same probe image always scores
/// the same way against a given candidate, but different probes or
/// candidates score differently — enough to exercise the ranked-candidate
/// workflow without a real embedding model. Never issues a match/no-match
/// verdict itself; it only ever produces a ranked, scored list for human
/// review, per the "candidates, not verdicts" principle in CLAUDE.md.
pub struct MockBiometricProvider;

impl BiometricProvider for MockBiometricProvider {
    fn search(&self, probe: &[u8], candidates: Vec<CandidateRow>, top_k: usize) -> Vec<ScoredCandidate> {
        let mut scored: Vec<ScoredCandidate> = candidates
            .into_iter()
            .map(|candidate| {
                let mut hasher = DefaultHasher::new();
                probe.hash(&mut hasher);
                candidate.id.hash(&mut hasher);
                let bucket = hasher.finish() % 5501; // 0..=5500
                let score = 0.40 + (bucket as f64) / 10000.0; // 0.4000..=0.9500
                ScoredCandidate { candidate, score }
            })
            .collect();
        scored.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal));
        scored.truncate(top_k);
        scored
    }
}
