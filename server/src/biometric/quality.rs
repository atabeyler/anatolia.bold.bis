//! Real, working classical-CV image-quality heuristics — not a trained
//! model. Documented honestly as heuristic (not ML-based) quality
//! assessment: blur via Laplacian-variance, lighting via a brightness
//! histogram, pose via 5-point landmark symmetry, and face size as a
//! fraction of the source image. Each threshold is a deliberately
//! conservative starting point, not a calibrated value — no labeled
//! dataset exists in this environment to calibrate against (see
//! `docs/SECURITY_ARCHITECTURE.md`). Occlusion detection is explicitly
//! *not* implemented here: a reliable heuristic for occlusion doesn't
//! exist without a trained model, and CLAUDE.md forbids faking
//! unimplemented capabilities.

use super::detection::FaceBox;
use super::BiometricError;

/// Minimum acceptable face bounding-box height as a fraction of the source
/// image's shorter dimension.
const MIN_FACE_SIZE_RATIO: f32 = 0.10;
/// Laplacian-variance floor below which a crop is judged too blurry.
/// Computed over the grayscale-converted face crop.
const MIN_LAPLACIAN_VARIANCE: f64 = 60.0;
/// Mean-brightness band (0-255) outside of which lighting is judged poor.
const MIN_MEAN_BRIGHTNESS: f64 = 40.0;
const MAX_MEAN_BRIGHTNESS: f64 = 215.0;
/// Landmark-symmetry ratio floor/ceiling for the horizontal eye-to-nose
/// distances; outside this band the face is judged too rotated (yaw) to
/// trust for matching.
const MIN_EYE_SYMMETRY_RATIO: f32 = 0.35;

pub fn check_face_size(
    face: &FaceBox,
    image_width: u32,
    image_height: u32,
) -> Result<(), BiometricError> {
    let shorter = image_width.min(image_height) as f32;
    if shorter <= 0.0 || face.height / shorter < MIN_FACE_SIZE_RATIO {
        return Err(BiometricError::FaceTooSmall);
    }
    Ok(())
}

/// Coarse yaw estimate from the horizontal distance of each eye to the
/// nose tip: a frontal face has roughly symmetric left/right distances; a
/// strongly rotated face does not. Not a substitute for a trained pose
/// model — documented as coarse.
pub fn check_pose(face: &FaceBox) -> Result<(), BiometricError> {
    let (right_eye, left_eye, nose, _, _) = (
        face.landmarks[0],
        face.landmarks[1],
        face.landmarks[2],
        face.landmarks[3],
        face.landmarks[4],
    );
    let d_right = (nose.0 - right_eye.0).abs();
    let d_left = (left_eye.0 - nose.0).abs();
    let (shorter, longer) = if d_right < d_left {
        (d_right, d_left)
    } else {
        (d_left, d_right)
    };
    if longer <= 0.0 {
        return Err(BiometricError::ExcessivePose);
    }
    if shorter / longer < MIN_EYE_SYMMETRY_RATIO {
        return Err(BiometricError::ExcessivePose);
    }
    Ok(())
}

/// Blur (Laplacian variance) and lighting (mean brightness) checks over an
/// aligned RGB crop.
pub fn check_blur_and_lighting(aligned_rgb: &[u8], size: u32) -> Result<(), BiometricError> {
    let gray = to_grayscale(aligned_rgb, size, size);
    let brightness = gray.iter().sum::<f64>() / gray.len() as f64;
    if !(MIN_MEAN_BRIGHTNESS..=MAX_MEAN_BRIGHTNESS).contains(&brightness) {
        return Err(BiometricError::PoorLighting);
    }
    let variance = laplacian_variance(&gray, size, size);
    if variance < MIN_LAPLACIAN_VARIANCE {
        return Err(BiometricError::ImageTooBlurry);
    }
    Ok(())
}

pub fn check_detection_confidence(face: &FaceBox, min_score: f32) -> Result<(), BiometricError> {
    if face.score < min_score {
        return Err(BiometricError::LowFaceQuality);
    }
    Ok(())
}

fn to_grayscale(rgb: &[u8], width: u32, height: u32) -> Vec<f64> {
    let mut out = Vec::with_capacity((width * height) as usize);
    for px in rgb.chunks_exact(3) {
        let r = px[0] as f64;
        let g = px[1] as f64;
        let b = px[2] as f64;
        out.push(0.299 * r + 0.587 * g + 0.114 * b);
    }
    out
}

/// Variance of the discrete Laplacian (edge response) over a grayscale
/// buffer — a standard, real blur heuristic: sharp images have high-
/// variance edge responses, blurry images have low-variance ones.
fn laplacian_variance(gray: &[f64], width: u32, height: u32) -> f64 {
    let w = width as i64;
    let h = height as i64;
    let mut responses = Vec::with_capacity(gray.len());
    let at = |x: i64, y: i64| -> f64 {
        let x = x.clamp(0, w - 1);
        let y = y.clamp(0, h - 1);
        gray[(y * w + x) as usize]
    };
    for y in 0..h {
        for x in 0..w {
            let value = -4.0 * at(x, y) + at(x - 1, y) + at(x + 1, y) + at(x, y - 1) + at(x, y + 1);
            responses.push(value);
        }
    }
    let mean = responses.iter().sum::<f64>() / responses.len() as f64;
    responses.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / responses.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn face_box(width: f32, height: f32, landmarks: [(f32, f32); 5]) -> FaceBox {
        FaceBox {
            x: 0.0,
            y: 0.0,
            width,
            height,
            score: 0.95,
            landmarks,
        }
    }

    #[test]
    fn small_face_is_rejected() {
        let face = face_box(20.0, 20.0, [(0.0, 0.0); 5]);
        assert!(check_face_size(&face, 640, 640).is_err());
    }

    #[test]
    fn large_enough_face_passes() {
        let face = face_box(200.0, 200.0, [(0.0, 0.0); 5]);
        assert!(check_face_size(&face, 640, 640).is_ok());
    }

    #[test]
    fn symmetric_landmarks_pass_pose_check() {
        let face = face_box(
            100.0,
            100.0,
            [
                (30.0, 40.0), // right eye
                (70.0, 40.0), // left eye
                (50.0, 60.0), // nose
                (35.0, 80.0),
                (65.0, 80.0),
            ],
        );
        assert!(check_pose(&face).is_ok());
    }

    #[test]
    fn heavily_asymmetric_landmarks_fail_pose_check() {
        let face = face_box(
            100.0,
            100.0,
            [
                (48.0, 40.0), // right eye very close to nose x
                (95.0, 40.0), // left eye far from nose x
                (50.0, 60.0), // nose
                (35.0, 80.0),
                (65.0, 80.0),
            ],
        );
        assert!(matches!(
            check_pose(&face),
            Err(BiometricError::ExcessivePose)
        ));
    }

    #[test]
    fn uniform_gray_image_has_zero_laplacian_variance_and_is_flagged_blurry() {
        let flat = vec![128u8; (112 * 112 * 3) as usize];
        assert!(matches!(
            check_blur_and_lighting(&flat, 112),
            Err(BiometricError::ImageTooBlurry)
        ));
    }

    #[test]
    fn very_dark_image_is_flagged_poor_lighting() {
        let dark = vec![5u8; (112 * 112 * 3) as usize];
        assert!(matches!(
            check_blur_and_lighting(&dark, 112),
            Err(BiometricError::PoorLighting)
        ));
    }

    #[test]
    fn checkerboard_pattern_has_high_variance_and_passes_blur_check() {
        let size = 112u32;
        let mut buf = vec![0u8; (size * size * 3) as usize];
        for y in 0..size {
            for x in 0..size {
                let value = if (x + y) % 2 == 0 { 220u8 } else { 30u8 };
                let idx = ((y * size + x) * 3) as usize;
                buf[idx] = value;
                buf[idx + 1] = value;
                buf[idx + 2] = value;
            }
        }
        assert!(check_blur_and_lighting(&buf, size).is_ok());
    }

    #[test]
    fn low_confidence_detection_fails_quality_check() {
        let mut face = face_box(200.0, 200.0, [(0.0, 0.0); 5]);
        face.score = 0.5;
        assert!(matches!(
            check_detection_confidence(&face, 0.9),
            Err(BiometricError::LowFaceQuality)
        ));
    }
}
