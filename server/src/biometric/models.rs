//! Model acquisition for the ONNX biometric provider.
//!
//! Both models come from the OpenCV Zoo (`github.com/opencv/opencv_zoo`),
//! fetched over `media.githubusercontent.com` (the actual LFS-backed binary
//! host — plain `raw.githubusercontent.com` only returns the Git LFS
//! pointer text for these files). Every download is verified against a
//! pinned SHA-256 hash before it is trusted; a mismatch is a hard error,
//! never a silent fallback. This satisfies the "fail closed" requirement:
//! if `BIOMETRIC_PROVIDER=onnx` is configured but the models cannot be
//! fetched or verified, startup fails rather than silently degrading to
//! the mock provider.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub struct ModelSpec {
    pub file_name: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
    pub license: &'static str,
}

/// YuNet face detector, `2023mar` release. Apache-2.0 (opencv_zoo).
pub const YUNET: ModelSpec = ModelSpec {
    file_name: "face_detection_yunet_2023mar.onnx",
    url: "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx",
    sha256: "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4",
    license: "Apache-2.0",
};

/// SFace face-recognition (embedding) model, `2021dec` release. MIT
/// (Copyright (c) 2020 Shiqi Yu <shiqi.yu@gmail.com>).
pub const SFACE: ModelSpec = ModelSpec {
    file_name: "face_recognition_sface_2021dec.onnx",
    url: "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx",
    sha256: "0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79",
    license: "MIT",
};

#[derive(Debug)]
pub enum ModelError {
    Io(String),
    Http(String),
    HashMismatch { expected: String, actual: String },
}

impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelError::Io(msg) => write!(f, "model I/O error: {msg}"),
            ModelError::Http(msg) => write!(f, "model download error: {msg}"),
            ModelError::HashMismatch { expected, actual } => {
                write!(f, "model hash mismatch: expected {expected}, got {actual}")
            }
        }
    }
}

impl std::error::Error for ModelError {}

fn cache_dir() -> PathBuf {
    PathBuf::from(std::env::var("MODEL_CACHE_DIR").unwrap_or_else(|_| "./data/models".to_string()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Ensures `spec` is present, verified, and up to date in the model cache
/// directory, downloading it if necessary. Returns the local path.
/// Never returns a path to unverified or mismatched bytes: on hash
/// mismatch, the bad download is removed rather than left on disk.
pub async fn ensure_model(spec: &ModelSpec) -> Result<PathBuf, ModelError> {
    let dir = cache_dir();
    std::fs::create_dir_all(&dir).map_err(|e| ModelError::Io(e.to_string()))?;
    let path = dir.join(spec.file_name);

    if path.exists() {
        let bytes = std::fs::read(&path).map_err(|e| ModelError::Io(e.to_string()))?;
        if sha256_hex(&bytes) == spec.sha256 {
            return Ok(path);
        }
        // Stale or corrupted cache entry — remove and re-download below.
        let _ = std::fs::remove_file(&path);
    }

    download_and_verify(spec, &path).await?;
    Ok(path)
}

async fn download_and_verify(spec: &ModelSpec, dest: &Path) -> Result<(), ModelError> {
    let response = reqwest::get(spec.url)
        .await
        .map_err(|e| ModelError::Http(e.to_string()))?;
    if !response.status().is_success() {
        return Err(ModelError::Http(format!(
            "unexpected status {} fetching {}",
            response.status(),
            spec.url
        )));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|e| ModelError::Http(e.to_string()))?;
    let actual = sha256_hex(&bytes);
    if actual != spec.sha256 {
        return Err(ModelError::HashMismatch {
            expected: spec.sha256.to_string(),
            actual,
        });
    }
    let tmp = dest.with_extension("onnx.partial");
    std::fs::write(&tmp, &bytes).map_err(|e| ModelError::Io(e.to_string()))?;
    std::fs::rename(&tmp, dest).map_err(|e| ModelError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        // SHA-256("abc")
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn cache_dir_defaults_when_unset() {
        std::env::remove_var("MODEL_CACHE_DIR");
        assert_eq!(cache_dir(), PathBuf::from("./data/models"));
    }

    #[test]
    fn hash_mismatch_removes_no_valid_file_and_reports_both_hashes() {
        let err = ModelError::HashMismatch {
            expected: "a".repeat(64),
            actual: "b".repeat(64),
        };
        let msg = err.to_string();
        assert!(msg.contains(&"a".repeat(64)));
        assert!(msg.contains(&"b".repeat(64)));
    }
}
