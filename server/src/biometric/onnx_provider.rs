//! Composes detection → quality gating → alignment → embedding →
//! stored-template search into a real `BiometricProvider` implementation,
//! backed by ONNX Runtime (`ort`) running the YuNet/SFace models — see
//! `docs/SECURITY_ARCHITECTURE.md` for what this pipeline does and does
//! not guarantee.
//!
//! `process_image`'s detect/align/embed pipeline is synchronous,
//! CPU-bound work (`ort::Session::run` blocks the calling thread), so
//! `search`/`enroll` run it via `tokio::task::block_in_place` rather than
//! directly on the async executor — that hands the current worker thread
//! over to blocking work and lets Tokio spin up a replacement worker for
//! other tasks, instead of starving them. This requires the
//! multi-threaded runtime (`rt-multi-thread`, already enabled in
//! `Cargo.toml`) and panics if called from a current-thread runtime.
//! `spawn_blocking` was not used here because `BiometricProvider::search`/
//! `enroll` take `&self`, not an owned `Arc<Self>`, so the closure cannot
//! satisfy `spawn_blocking`'s `'static` bound without unsafe lifetime
//! extension.

use std::path::PathBuf;
use std::sync::Mutex;

use crate::db::{load_candidate_by_id, search_top_k, AppState};

use super::alignment::align_face;
use super::detection::FaceDetector;
use super::embedding::EmbeddingProvider;
use super::models::{ensure_model, SFACE, YUNET};
use super::quality::{
    check_blur_and_lighting, check_detection_confidence, check_face_size, check_pose,
};
use super::{BiometricError, BiometricProvider, EnrollmentResult, ScoredCandidate};

pub const MODEL_NAME: &str = "sface";
pub const MODEL_VERSION: &str = "2021dec";
/// Minimum YuNet detection confidence a probe's chosen face must clear —
/// distinct from (and above) the raw `SCORE_THRESHOLD` used to accept a
/// candidate detection in the first place, since a search probe deserves a
/// stricter bar than "detected at all".
const MIN_SEARCH_CONFIDENCE: f32 = 0.92;
/// Slightly lower bar for enrollment reference photos than search probes:
/// a reference photo is typically curated/controlled at capture time, so
/// this only rejects clearly unusable detections rather than applying the
/// stricter probe-time bar.
const MIN_ENROLLMENT_CONFIDENCE: f32 = 0.9;

pub struct OnnxBiometricProvider {
    detector: Mutex<FaceDetector>,
    embedder: Mutex<EmbeddingProvider>,
}

impl OnnxBiometricProvider {
    /// Downloads (if needed) and loads both models, verifying each against
    /// its pinned SHA-256 hash. Fails closed: returns `Err` rather than
    /// falling back to any other provider if either model can't be
    /// fetched, verified, or loaded into ONNX Runtime.
    pub async fn initialize() -> Result<Self, BiometricError> {
        let yunet_path = ensure_model(&YUNET)
            .await
            .map_err(|e| BiometricError::ProviderUnavailable(e.to_string()))?;
        let sface_path = ensure_model(&SFACE)
            .await
            .map_err(|e| BiometricError::ProviderUnavailable(e.to_string()))?;
        let detector = load_detector(yunet_path)?;
        let embedder = load_embedder(sface_path)?;
        Ok(Self {
            detector: Mutex::new(detector),
            embedder: Mutex::new(embedder),
        })
    }

    /// Runs the full detect → quality → align → embed pipeline over a
    /// single probe/reference image, returning its embedding, the
    /// detector's confidence score, and the accepted image's width/height
    /// for callers (like the enrollment endpoint) that need more than just
    /// the final vector. `min_confidence` lets the caller apply a stricter
    /// bar for search probes than for enrollment references, or vice
    /// versa.
    pub fn process_image(
        &self,
        rgb: &[u8],
        width: u32,
        height: u32,
        min_confidence: f32,
    ) -> Result<(Vec<f32>, f32), BiometricError> {
        let boxes = {
            let mut detector = self
                .detector
                .lock()
                .map_err(|_| BiometricError::Internal("detector lock poisoned".to_string()))?;
            detector
                .detect(rgb, width, height)
                .map_err(|e| BiometricError::Internal(e.to_string()))?
        };

        if boxes.is_empty() {
            return Err(BiometricError::NoFaceDetected);
        }
        if boxes.len() > 1 {
            return Err(BiometricError::MultipleFacesDetected { count: boxes.len() });
        }
        let face = &boxes[0];

        check_detection_confidence(face, min_confidence)?;
        check_face_size(face, width, height)?;
        check_pose(face)?;

        let aligned = align_face(rgb, width, height, &face.landmarks);
        check_blur_and_lighting(&aligned, super::alignment::ALIGNED_SIZE)?;

        let embedding = {
            let mut embedder = self
                .embedder
                .lock()
                .map_err(|_| BiometricError::Internal("embedder lock poisoned".to_string()))?;
            embedder
                .embed(&aligned)
                .map_err(|e| BiometricError::Internal(e.to_string()))?
        };

        Ok((embedding, face.score))
    }
}

fn load_detector(path: PathBuf) -> Result<FaceDetector, BiometricError> {
    FaceDetector::load(&path).map_err(|e| BiometricError::ProviderUnavailable(e.to_string()))
}

fn load_embedder(path: PathBuf) -> Result<EmbeddingProvider, BiometricError> {
    EmbeddingProvider::load(&path).map_err(|e| BiometricError::ProviderUnavailable(e.to_string()))
}

#[async_trait::async_trait]
impl BiometricProvider for OnnxBiometricProvider {
    async fn search(
        &self,
        state: &AppState,
        probe: &[u8],
        top_k: usize,
    ) -> Result<Vec<ScoredCandidate>, BiometricError> {
        let decoded = image::load_from_memory(probe)
            .map_err(|e| BiometricError::Internal(e.to_string()))?
            .to_rgb8();
        let (width, height) = (decoded.width(), decoded.height());
        let rgb = decoded.into_raw();

        let (probe_embedding, _confidence) = tokio::task::block_in_place(|| {
            self.process_image(&rgb, width, height, MIN_SEARCH_CONFIDENCE)
        })?;

        let matches = search_top_k(
            &state.backend,
            MODEL_NAME,
            MODEL_VERSION,
            &probe_embedding,
            top_k,
            state.pgvector_search_ready,
        )
        .await
        .map_err(|e| BiometricError::Internal(e.to_string()))?;

        let mut scored = Vec::with_capacity(matches.len());
        for m in matches {
            if let Ok(Some(candidate)) = load_candidate_by_id(&state.backend, &m.candidate_id).await
            {
                scored.push(ScoredCandidate {
                    candidate,
                    score: m.score,
                });
            }
        }
        Ok(scored)
    }

    async fn enroll(&self, image_bytes: &[u8]) -> Result<EnrollmentResult, BiometricError> {
        let decoded = image::load_from_memory(image_bytes)
            .map_err(|e| BiometricError::Internal(e.to_string()))?
            .to_rgb8();
        let (width, height) = (decoded.width(), decoded.height());
        let rgb = decoded.into_raw();

        let (embedding, confidence) = tokio::task::block_in_place(|| {
            self.process_image(&rgb, width, height, MIN_ENROLLMENT_CONFIDENCE)
        })?;

        Ok(EnrollmentResult {
            embedding,
            quality_score: confidence as f64,
            model_name: MODEL_NAME.to_string(),
            model_version: MODEL_VERSION.to_string(),
        })
    }
}
