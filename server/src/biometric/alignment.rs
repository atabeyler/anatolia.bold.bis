//! Face alignment: warps a detected face's 5-point landmarks onto the
//! fixed 112x112 reference template SFace/ArcFace-family models expect,
//! via a least-squares similarity transform (Umeyama's method). The
//! reference coordinates below are the exact constants OpenCV's
//! `FaceRecognizerSF::alignCrop` uses (`modules/objdetect/src/face_recognize.cpp`).

/// Right eye, left eye, nose tip, right mouth corner, left mouth corner —
/// same convention YuNet's landmarks use, at their expected position in a
/// 112x112 aligned crop.
const REFERENCE_LANDMARKS: [(f32, f32); 5] = [
    (38.2946, 51.6963),
    (73.5318, 51.5014),
    (56.0252, 71.7366),
    (41.5493, 92.3655),
    (70.7299, 92.2041),
];

pub const ALIGNED_SIZE: u32 = 112;

/// A 2x3 affine transform: `[a b tx; c d ty]`.
#[derive(Debug, Clone, Copy)]
pub struct AffineTransform {
    pub a: f64,
    pub b: f64,
    pub c: f64,
    pub d: f64,
    pub tx: f64,
    pub ty: f64,
}

impl AffineTransform {
    #[cfg(test)]
    fn apply(&self, x: f32, y: f32) -> (f32, f32) {
        let x = x as f64;
        let y = y as f64;
        (
            (self.a * x + self.b * y + self.tx) as f32,
            (self.c * x + self.d * y + self.ty) as f32,
        )
    }
}

/// Least-squares similarity transform (rotation + uniform scale +
/// translation, no shear/reflection) mapping `src` points onto `dst`
/// points as closely as possible — the 2D closed form of Umeyama's method
/// (Kabsch algorithm restricted to a rotation, plus the standard scale
/// term). For 2D specifically, the optimal rotation angle maximizing
/// `sum(dot(R * src_i, dst_i))` over centered point pairs has the direct
/// closed form `theta = atan2(B, A)` derived below (no general SVD
/// needed), which sidesteps having to implement a general 2x2 SVD.
pub fn similarity_transform(src: &[(f32, f32); 5], dst: &[(f32, f32); 5]) -> AffineTransform {
    let n = src.len() as f64;

    let src_mean_x = src.iter().map(|p| p.0 as f64).sum::<f64>() / n;
    let src_mean_y = src.iter().map(|p| p.1 as f64).sum::<f64>() / n;
    let dst_mean_x = dst.iter().map(|p| p.0 as f64).sum::<f64>() / n;
    let dst_mean_y = dst.iter().map(|p| p.1 as f64).sum::<f64>() / n;

    // A = sum(dot(centered_dst, centered_src)),
    // B = sum(cross(centered_src, centered_dst))
    // maximizing cos(theta)*A + sin(theta)*B => theta = atan2(B, A).
    let mut a = 0.0f64;
    let mut b = 0.0f64;
    let mut src_var = 0.0f64;
    for i in 0..src.len() {
        let sx = src[i].0 as f64 - src_mean_x;
        let sy = src[i].1 as f64 - src_mean_y;
        let dx = dst[i].0 as f64 - dst_mean_x;
        let dy = dst[i].1 as f64 - dst_mean_y;
        a += dx * sx + dy * sy;
        b += dy * sx - dx * sy;
        src_var += sx * sx + sy * sy;
    }

    let theta = b.atan2(a);
    let (sin_t, cos_t) = theta.sin_cos();
    let scale = if src_var > 1e-12 {
        (a * a + b * b).sqrt() / src_var
    } else {
        1.0
    };

    let r00 = cos_t;
    let r01 = -sin_t;
    let r10 = sin_t;
    let r11 = cos_t;

    let tx = dst_mean_x - scale * (r00 * src_mean_x + r01 * src_mean_y);
    let ty = dst_mean_y - scale * (r10 * src_mean_x + r11 * src_mean_y);

    AffineTransform {
        a: scale * r00,
        b: scale * r01,
        c: scale * r10,
        d: scale * r11,
        tx,
        ty,
    }
}

/// Warps `src` (interleaved RGB, `src_w`x`src_h`) using `transform` to
/// produce a 112x112 aligned RGB crop, matching SFace's expected input.
pub fn warp_to_aligned(src: &[u8], src_w: u32, src_h: u32, transform: &AffineTransform) -> Vec<u8> {
    let size = ALIGNED_SIZE;
    let mut out = vec![0u8; (size * size * 3) as usize];
    // Invert the transform so we can sample source pixels for each
    // destination pixel (standard inverse warping to avoid holes).
    let det = transform.a * transform.d - transform.b * transform.c;
    if det.abs() < 1e-12 {
        return out;
    }
    let inv_a = transform.d / det;
    let inv_b = -transform.b / det;
    let inv_c = -transform.c / det;
    let inv_d = transform.a / det;
    let inv_tx = -(inv_a * transform.tx + inv_b * transform.ty);
    let inv_ty = -(inv_c * transform.tx + inv_d * transform.ty);

    for dy in 0..size {
        for dx in 0..size {
            let sx = inv_a * dx as f64 + inv_b * dy as f64 + inv_tx;
            let sy = inv_c * dx as f64 + inv_d * dy as f64 + inv_ty;
            let (r, g, b) = sample_bilinear(src, src_w, src_h, sx as f32, sy as f32);
            let out_idx = ((dy * size + dx) * 3) as usize;
            out[out_idx] = r;
            out[out_idx + 1] = g;
            out[out_idx + 2] = b;
        }
    }
    out
}

fn sample_bilinear(src: &[u8], w: u32, h: u32, x: f32, y: f32) -> (u8, u8, u8) {
    if x < 0.0 || y < 0.0 || x >= (w - 1) as f32 || y >= (h - 1) as f32 {
        return (0, 0, 0);
    }
    let x0 = x.floor() as u32;
    let y0 = y.floor() as u32;
    let x1 = (x0 + 1).min(w - 1);
    let y1 = (y0 + 1).min(h - 1);
    let fx = x - x0 as f32;
    let fy = y - y0 as f32;
    let mut out = [0u8; 3];
    for ch in 0..3 {
        let p00 = src[((y0 * w + x0) * 3 + ch) as usize] as f32;
        let p10 = src[((y0 * w + x1) * 3 + ch) as usize] as f32;
        let p01 = src[((y1 * w + x0) * 3 + ch) as usize] as f32;
        let p11 = src[((y1 * w + x1) * 3 + ch) as usize] as f32;
        let top = p00 + (p10 - p00) * fx;
        let bottom = p01 + (p11 - p01) * fx;
        out[ch as usize] = (top + (bottom - top) * fy).round().clamp(0.0, 255.0) as u8;
    }
    (out[0], out[1], out[2])
}

/// Convenience: computes the alignment transform for `landmarks` against
/// the fixed reference template and warps `src` in one call.
pub fn align_face(src: &[u8], src_w: u32, src_h: u32, landmarks: &[(f32, f32); 5]) -> Vec<u8> {
    let transform = similarity_transform(landmarks, &REFERENCE_LANDMARKS);
    warp_to_aligned(src, src_w, src_h, &transform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_landmarks_produce_identity_like_transform() {
        let transform = similarity_transform(&REFERENCE_LANDMARKS, &REFERENCE_LANDMARKS);
        for &(x, y) in REFERENCE_LANDMARKS.iter() {
            let (ox, oy) = transform.apply(x, y);
            assert!((ox - x).abs() < 1e-3, "x mismatch: {ox} vs {x}");
            assert!((oy - y).abs() < 1e-3, "y mismatch: {oy} vs {y}");
        }
    }

    #[test]
    fn pure_translation_is_recovered() {
        let shifted: [(f32, f32); 5] = REFERENCE_LANDMARKS.map(|(x, y)| (x + 10.0, y - 5.0));
        let transform = similarity_transform(&shifted, &REFERENCE_LANDMARKS);
        let (ox, oy) = transform.apply(shifted[0].0, shifted[0].1);
        assert!((ox - REFERENCE_LANDMARKS[0].0).abs() < 1e-2);
        assert!((oy - REFERENCE_LANDMARKS[0].1).abs() < 1e-2);
    }

    #[test]
    fn uniform_scale_is_recovered() {
        let scaled: [(f32, f32); 5] = REFERENCE_LANDMARKS.map(|(x, y)| (x * 2.0, y * 2.0));
        let transform = similarity_transform(&scaled, &REFERENCE_LANDMARKS);
        for &(x, y) in scaled.iter() {
            let (ox, oy) = transform.apply(x, y);
            let expected = (x / 2.0, y / 2.0);
            assert!((ox - expected.0).abs() < 1e-2);
            assert!((oy - expected.1).abs() < 1e-2);
        }
    }

    #[test]
    fn warp_of_uniform_image_stays_uniform() {
        let src = vec![100u8; (200 * 200 * 3) as usize];
        let transform = AffineTransform {
            a: 1.0,
            b: 0.0,
            c: 0.0,
            d: 1.0,
            tx: 0.0,
            ty: 0.0,
        };
        let out = warp_to_aligned(&src, 200, 200, &transform);
        assert_eq!(out.len(), (ALIGNED_SIZE * ALIGNED_SIZE * 3) as usize);
        // Interior pixels (not clipped by the out-of-bounds guard) should
        // sample the uniform source color.
        let center_idx = ((56 * ALIGNED_SIZE + 56) * 3) as usize;
        assert_eq!(out[center_idx], 100);
    }
}
