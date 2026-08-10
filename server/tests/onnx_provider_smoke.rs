//! Opt-in smoke test for the real ONNX biometric pipeline: downloads the
//! pinned YuNet/SFace models, loads them into ONNX Runtime, and runs a
//! synthetic (non-face) image through the full detect/quality/align/embed
//! path. This proves the runtime — model download + SHA-256 verification +
//! `ort::Session` construction + inference — works end to end in a given
//! environment, without touching any real photograph: a synthetic image
//! has no face to detect, so the expected, successful outcome here is
//! `BiometricError::NoFaceDetected`, not a match.
//!
//! Verifying real match/non-match accuracy needs real face images and is
//! deliberately out of scope for this repository — see CLAUDE.md ("never
//! commit ... real subject photographs") and `calibrate.rs`, which is the
//! tool for evaluating FAR/FRR against an authorized, consented dataset
//! kept outside version control.
//!
//! Ignored by default: requires the `onnx-provider` feature and network
//! access to download the models on first run. Run explicitly with:
//!   cargo test --release --features onnx-provider --test onnx_provider_smoke -- --ignored

#![cfg(feature = "onnx-provider")]

use anatolia_bis_server::biometric::onnx_provider::OnnxBiometricProvider;
use anatolia_bis_server::biometric::BiometricError;

#[tokio::test]
#[ignore]
async fn pipeline_initializes_and_runs_on_a_synthetic_image() {
    let provider = OnnxBiometricProvider::initialize()
        .await
        .expect("model download, verification, and ONNX session load should succeed");

    let width = 320u32;
    let height = 240u32;
    let rgb: Vec<u8> = (0..(width * height * 3))
        .map(|i| ((i * 37) % 256) as u8)
        .collect();

    let result = provider.process_image(&rgb, width, height, 0.9);
    match result {
        Err(BiometricError::NoFaceDetected) => {}
        other => panic!("expected NoFaceDetected on a synthetic non-face image, got {other:?}"),
    }
}
