//! Face embedding extraction via SFace, run through ONNX Runtime.
//!
//! Preprocessing matches OpenCV's `FaceRecognizerSF::feature`, which calls
//! `dnn::blobFromImage(_aligned_img, 1, Size(112, 112), Scalar(0,0,0),
//! true, false)` — scale factor 1 (raw 0-255 float pixel values), no mean
//! subtraction, `swapRB=true`. Since OpenCV reads images as BGR by default,
//! `swapRB=true` there converts to RGB before feeding the network; this
//! codebase already decodes images as RGB, so no channel swap is needed
//! here. The model's only real input is `data` (`[1,3,112,112]`, NCHW) —
//! confirmed by loading the model with `onnx.load` and checking which
//! `graph.input` entries are not also present as `graph.initializer`
//! (every other declared input is a baked-in weight tensor, an artifact of
//! this model's mxnet-to-onnx export). Output `fc1` is a 128-dim feature
//! vector; OpenCV only L2-normalizes it inside `match()`, not inside
//! `feature()`, so normalization is done explicitly here before storing.

use ort::session::Session;
use ort::value::Tensor;

use super::alignment::ALIGNED_SIZE;

pub const EMBEDDING_DIM: usize = 128;

pub struct EmbeddingProvider {
    session: Session,
}

impl EmbeddingProvider {
    pub fn load(model_path: &std::path::Path) -> Result<Self, ort::Error> {
        let session = Session::builder()?.commit_from_file(model_path)?;
        Ok(Self { session })
    }

    /// `aligned_rgb` must be a 112x112 interleaved RGB buffer, as produced
    /// by `alignment::align_face`. Returns an L2-normalized 128-dim vector.
    pub fn embed(&mut self, aligned_rgb: &[u8]) -> Result<Vec<f32>, ort::Error> {
        let size = ALIGNED_SIZE as usize;
        let mut data = vec![0f32; 3 * size * size];
        for y in 0..size {
            for x in 0..size {
                let px = (y * size + x) * 3;
                let r = aligned_rgb[px] as f32;
                let g = aligned_rgb[px + 1] as f32;
                let b = aligned_rgb[px + 2] as f32;
                data[y * size + x] = r;
                data[size * size + y * size + x] = g;
                data[2 * size * size + y * size + x] = b;
            }
        }
        let input = Tensor::from_array(([1usize, 3, size, size], data))?;
        let outputs = self.session.run(ort::inputs!["data" => input])?;
        let raw = outputs["fc1"].try_extract_array::<f32>()?;
        let raw = raw.as_slice().expect("fc1 tensor is contiguous").to_vec();
        Ok(l2_normalize(raw))
    }
}

pub fn l2_normalize(mut v: Vec<f32>) -> Vec<f32> {
    let norm = (v.iter().map(|x| (*x as f64) * (*x as f64)).sum::<f64>()).sqrt();
    if norm > 1e-12 {
        for x in v.iter_mut() {
            *x = (*x as f64 / norm) as f32;
        }
    }
    v
}

pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let dot: f64 = a.iter().zip(b).map(|(x, y)| *x as f64 * *y as f64).sum();
    let norm_a = a.iter().map(|x| (*x as f64).powi(2)).sum::<f64>().sqrt();
    let norm_b = b.iter().map(|x| (*x as f64).powi(2)).sum::<f64>().sqrt();
    if norm_a <= 1e-12 || norm_b <= 1e-12 {
        0.0
    } else {
        (dot / (norm_a * norm_b)).clamp(-1.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l2_normalize_produces_unit_vector() {
        let v = vec![3.0, 4.0];
        let normalized = l2_normalize(v);
        let norm = (normalized[0].powi(2) + normalized[1].powi(2)).sqrt();
        assert!((norm - 1.0).abs() < 1e-5);
        assert!((normalized[0] - 0.6).abs() < 1e-5);
        assert!((normalized[1] - 0.8).abs() < 1e-5);
    }

    #[test]
    fn l2_normalize_leaves_zero_vector_unchanged() {
        let v = vec![0.0, 0.0, 0.0];
        assert_eq!(l2_normalize(v), vec![0.0, 0.0, 0.0]);
    }

    #[test]
    fn cosine_similarity_of_identical_vectors_is_one() {
        let v = vec![0.1, 0.2, 0.3, 0.4];
        assert!((cosine_similarity(&v, &v) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_of_orthogonal_vectors_is_zero() {
        let a = vec![1.0, 0.0];
        let b = vec![0.0, 1.0];
        assert!(cosine_similarity(&a, &b).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_of_opposite_vectors_is_negative_one() {
        let a = vec![1.0, 0.0];
        let b = vec![-1.0, 0.0];
        assert!((cosine_similarity(&a, &b) + 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_mismatched_lengths_is_zero() {
        let a = vec![1.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert_eq!(cosine_similarity(&a, &b), 0.0);
    }
}
