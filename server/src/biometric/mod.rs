//! `BiometricProvider` abstraction (see CLAUDE.md's architecture notes).
//!
//! Two implementations exist:
//! - `MockBiometricProvider`: deterministic, content-seeded scoring with no
//!   real face analysis. Used when `BIOMETRIC_PROVIDER=mock` (the default
//!   outside production). Kept so the full search workflow stays
//!   developable/testable without a real model.
//! - `OnnxBiometricProvider` (`onnx_provider.rs`): a real, server-side
//!   pipeline — YuNet face detection, heuristic quality gating, 5-point
//!   similarity-transform alignment, and SFace face-embedding extraction,
//!   all run through ONNX Runtime (`ort`) — behind `BIOMETRIC_PROVIDER=onnx`.
//!   See `docs/SECURITY_ARCHITECTURE.md` for exactly what this does and does
//!   not guarantee.
//!
//! The trait is async and DB-querying (rather than receiving a pre-loaded
//! `Vec<CandidateRow>`) so a real provider can run a real Top-K vector
//! search against stored embeddings instead of the caller loading the
//! entire candidate table into memory on every search.

pub mod alignment;
pub mod detection;
pub mod embedding;
#[cfg(feature = "onnx-provider")]
pub mod models;
#[cfg(feature = "onnx-provider")]
pub mod onnx_provider;
pub mod quality;

use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::db::{AppState, CandidateRow};

pub use detection::FaceBox;
#[cfg(feature = "onnx-provider")]
pub use onnx_provider::OnnxBiometricProvider;

pub struct ScoredCandidate {
    pub candidate: CandidateRow,
    pub score: f64,
}

/// Result of running the enrollment pipeline over a single reference
/// image: the embedding to store, the detector's confidence as a proxy
/// quality score, and which model/version produced it (so future
/// comparisons only ever happen between compatible embeddings).
pub struct EnrollmentResult {
    pub embedding: Vec<f32>,
    pub quality_score: f64,
    pub model_name: String,
    pub model_version: String,
}

/// Rejection reasons a real biometric pipeline can raise before it ever
/// produces a ranked candidate list. Each maps to a stable API error code
/// (see `error.rs`) so the caller gets an actionable reason rather than a
/// generic failure. `MockBiometricProvider` never raises any of these — it
/// performs no real face analysis, so there is nothing genuine to check.
#[derive(Debug)]
pub enum BiometricError {
    NoFaceDetected,
    MultipleFacesDetected { count: usize },
    FaceTooSmall,
    ImageTooBlurry,
    ExcessivePose,
    PoorLighting,
    LowFaceQuality,
    ProviderUnavailable(String),
    Internal(String),
}

impl BiometricError {
    pub fn code(&self) -> &'static str {
        match self {
            BiometricError::NoFaceDetected => "NO_FACE_DETECTED",
            BiometricError::MultipleFacesDetected { .. } => "MULTIPLE_FACES_DETECTED",
            BiometricError::FaceTooSmall => "FACE_TOO_SMALL",
            BiometricError::ImageTooBlurry => "IMAGE_TOO_BLURRY",
            BiometricError::ExcessivePose => "EXCESSIVE_POSE",
            BiometricError::PoorLighting => "POOR_LIGHTING",
            BiometricError::LowFaceQuality => "LOW_FACE_QUALITY",
            BiometricError::ProviderUnavailable(_) => "BIOMETRIC_PROVIDER_UNAVAILABLE",
            BiometricError::Internal(_) => "INTERNAL_ERROR",
        }
    }

    pub fn message_key(&self) -> &'static str {
        match self {
            BiometricError::NoFaceDetected => "errors.noFaceDetected",
            BiometricError::MultipleFacesDetected { .. } => "errors.multipleFacesDetected",
            BiometricError::FaceTooSmall => "errors.faceTooSmall",
            BiometricError::ImageTooBlurry => "errors.imageTooBlurry",
            BiometricError::ExcessivePose => "errors.excessivePose",
            BiometricError::PoorLighting => "errors.poorLighting",
            BiometricError::LowFaceQuality => "errors.lowFaceQuality",
            BiometricError::ProviderUnavailable(_) => "errors.biometricProviderUnavailable",
            BiometricError::Internal(_) => "errors.internal",
        }
    }
}

impl std::fmt::Display for BiometricError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BiometricError::MultipleFacesDetected { count } => {
                write!(f, "multiple faces detected ({count})")
            }
            BiometricError::ProviderUnavailable(msg) => write!(f, "provider unavailable: {msg}"),
            BiometricError::Internal(msg) => write!(f, "internal biometric error: {msg}"),
            other => write!(f, "{}", other.code()),
        }
    }
}

impl std::error::Error for BiometricError {}

#[async_trait::async_trait]
pub trait BiometricProvider: Send + Sync {
    /// Ranks every enrolled candidate against the probe image bytes,
    /// highest similarity first, capped at `top_k`. Looks up whatever data
    /// it needs itself (candidate list, stored templates) rather than
    /// requiring the caller to pre-load it.
    async fn search(
        &self,
        state: &AppState,
        probe: &[u8],
        top_k: usize,
    ) -> Result<Vec<ScoredCandidate>, BiometricError>;

    /// Runs the enrollment pipeline (detect → quality-gate → align →
    /// embed) over a single reference image, returning the embedding to
    /// store. `MockBiometricProvider` has no real embedding to produce and
    /// always returns `BiometricError::ProviderUnavailable` — enrollment
    /// is only meaningful under a real provider.
    async fn enroll(&self, image_bytes: &[u8]) -> Result<EnrollmentResult, BiometricError>;
}

/// Deterministic, content-seeded mock: the same probe image always scores
/// the same way against a given candidate, but different probes or
/// candidates score differently — enough to exercise the ranked-candidate
/// workflow without a real embedding model. Never issues a match/no-match
/// verdict itself; it only ever produces a ranked, scored list for human
/// review, per the "candidates, not verdicts" principle in CLAUDE.md.
/// Performs no real face detection or quality checks — it never raises any
/// `BiometricError` variant.
pub struct MockBiometricProvider;

#[async_trait::async_trait]
impl BiometricProvider for MockBiometricProvider {
    async fn search(
        &self,
        state: &AppState,
        probe: &[u8],
        top_k: usize,
    ) -> Result<Vec<ScoredCandidate>, BiometricError> {
        let candidates = crate::db::list_candidates(&state.backend)
            .await
            .map_err(|err| BiometricError::Internal(err.to_string()))?;
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
        Ok(scored)
    }

    async fn enroll(&self, _image_bytes: &[u8]) -> Result<EnrollmentResult, BiometricError> {
        Err(BiometricError::ProviderUnavailable(
            "the mock provider performs no real face embedding; enrollment requires \
             BIOMETRIC_PROVIDER=onnx"
                .to_string(),
        ))
    }
}
