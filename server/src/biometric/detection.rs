//! Face detection via YuNet, run through ONNX Runtime.
//!
//! YuNet's ONNX graph (`face_detection_yunet_2023mar.onnx`) only exports
//! raw per-stride classification/objectness/box/landmark tensors — the
//! anchor decoding and NMS that OpenCV's `FaceDetectorYN` normally performs
//! internally (in `modules/objdetect/src/face_detect.cpp`) are not part of
//! the graph and have to be reimplemented here to use the model outside
//! OpenCV's `dnn` module. The decode formulas below were taken directly
//! from that OpenCV source (`postProcess`), and the fixed input shape
//! (1×3×640×640) and output tensor names/shapes were confirmed by loading
//! the model with `onnx.load` and inspecting `graph.input`/`graph.output`.
//!
//! Preprocessing matches OpenCV's `blobFromImage(pad_image)` call, which
//! uses that function's defaults: no mean subtraction, scale factor 1, and
//! `swapRB=false` — meaning the network expects BGR channel order (OpenCV
//! decodes images as BGR by default). Since this codebase decodes images as
//! RGB, the R and B channels are swapped when building the input tensor.

use ort::session::Session;
use ort::value::Tensor;

pub const INPUT_SIZE: u32 = 640;
const STRIDES: [u32; 3] = [8, 16, 32];
const SCORE_THRESHOLD: f32 = 0.9;
const NMS_IOU_THRESHOLD: f32 = 0.3;
const PRE_NMS_TOP_K: usize = 5000;

/// A detected face in the coordinate space of the image that was passed to
/// `detect` (already rescaled from the 640x640 model input back to the
/// original image dimensions).
#[derive(Debug, Clone)]
pub struct FaceBox {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub score: f32,
    /// Five landmarks in (x, y) pairs: right eye, left eye, nose tip,
    /// right mouth corner, left mouth corner (YuNet's own convention).
    pub landmarks: [(f32, f32); 5],
}

pub struct FaceDetector {
    session: Session,
}

impl FaceDetector {
    pub fn load(model_path: &std::path::Path) -> Result<Self, ort::Error> {
        let session = Session::builder()?.commit_from_file(model_path)?;
        Ok(Self { session })
    }

    /// Runs detection over an RGB `width`x`height` image (`rgb.len() ==
    /// width*height*3`), returning every detected face above the score
    /// threshold, highest score first, with non-max suppression applied.
    pub fn detect(
        &mut self,
        rgb: &[u8],
        width: u32,
        height: u32,
    ) -> Result<Vec<FaceBox>, ort::Error> {
        let input = build_input_tensor(rgb, width, height);
        let outputs = self.session.run(ort::inputs![
            "input" => input,
        ])?;

        let mut candidates: Vec<FaceBox> = Vec::new();
        for &stride in STRIDES.iter() {
            let cols = (INPUT_SIZE / stride) as usize;
            let rows = (INPUT_SIZE / stride) as usize;
            let cls = outputs[format!("cls_{stride}")].try_extract_array::<f32>()?;
            let obj = outputs[format!("obj_{stride}")].try_extract_array::<f32>()?;
            let bbox = outputs[format!("bbox_{stride}")].try_extract_array::<f32>()?;
            let kps = outputs[format!("kps_{stride}")].try_extract_array::<f32>()?;
            let cls = cls.as_slice().expect("cls tensor is contiguous");
            let obj = obj.as_slice().expect("obj tensor is contiguous");
            let bbox = bbox.as_slice().expect("bbox tensor is contiguous");
            let kps = kps.as_slice().expect("kps tensor is contiguous");

            for r in 0..rows {
                for c in 0..cols {
                    let idx = r * cols + c;
                    let cls_score = cls[idx].clamp(0.0, 1.0);
                    let obj_score = obj[idx].clamp(0.0, 1.0);
                    let score = (cls_score * obj_score).sqrt();
                    if score < SCORE_THRESHOLD {
                        continue;
                    }
                    let dx = bbox[idx * 4];
                    let dy = bbox[idx * 4 + 1];
                    let dw = bbox[idx * 4 + 2];
                    let dh = bbox[idx * 4 + 3];
                    let stride_f = stride as f32;
                    let cx = (c as f32 + dx) * stride_f;
                    let cy = (r as f32 + dy) * stride_f;
                    let w = dw.exp() * stride_f;
                    let h = dh.exp() * stride_f;
                    let x = cx - w / 2.0;
                    let y = cy - h / 2.0;

                    let mut landmarks = [(0.0f32, 0.0f32); 5];
                    for n in 0..5 {
                        let lx = (kps[idx * 10 + 2 * n] + c as f32) * stride_f;
                        let ly = (kps[idx * 10 + 2 * n + 1] + r as f32) * stride_f;
                        landmarks[n] = (lx, ly);
                    }

                    candidates.push(FaceBox {
                        x,
                        y,
                        width: w,
                        height: h,
                        score,
                        landmarks,
                    });
                }
            }
        }

        candidates.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        candidates.truncate(PRE_NMS_TOP_K);
        let kept = non_max_suppression(candidates, NMS_IOU_THRESHOLD);

        // Rescale from the fixed 640x640 model input back to the caller's
        // original image dimensions (this provider resizes to 640x640
        // directly rather than letterboxing, so x/y scale independently).
        let sx = width as f32 / INPUT_SIZE as f32;
        let sy = height as f32 / INPUT_SIZE as f32;
        Ok(kept
            .into_iter()
            .map(|mut b| {
                b.x *= sx;
                b.y *= sy;
                b.width *= sx;
                b.height *= sy;
                for lm in b.landmarks.iter_mut() {
                    lm.0 *= sx;
                    lm.1 *= sy;
                }
                b
            })
            .collect())
    }
}

fn build_input_tensor(rgb: &[u8], width: u32, height: u32) -> Tensor<f32> {
    let resized = resize_bilinear_rgb(rgb, width, height, INPUT_SIZE, INPUT_SIZE);
    let size = INPUT_SIZE as usize;
    let mut data = vec![0f32; 3 * size * size];
    // NCHW, BGR order (swapRB=false relative to OpenCV's BGR decode) — see
    // module doc comment.
    for y in 0..size {
        for x in 0..size {
            let px = (y * size + x) * 3;
            let r = resized[px] as f32;
            let g = resized[px + 1] as f32;
            let b = resized[px + 2] as f32;
            data[y * size + x] = b;
            data[size * size + y * size + x] = g;
            data[2 * size * size + y * size + x] = r;
        }
    }
    Tensor::from_array(([1usize, 3, size, size], data)).expect("static tensor shape is valid")
}

/// Nearest-alternative-free bilinear resize of an interleaved RGB buffer.
/// Kept local (rather than pulling in `image::imageops`) so the exact same
/// function is reused for both YuNet's 640x640 input and SFace's aligned
/// 112x112 crop scaling if ever needed independently of `image`'s resizer.
pub fn resize_bilinear_rgb(src: &[u8], src_w: u32, src_h: u32, dst_w: u32, dst_h: u32) -> Vec<u8> {
    let mut out = vec![0u8; (dst_w * dst_h * 3) as usize];
    let x_ratio = src_w as f32 / dst_w as f32;
    let y_ratio = src_h as f32 / dst_h as f32;
    for dy in 0..dst_h {
        let sy = ((dy as f32 + 0.5) * y_ratio - 0.5).max(0.0);
        let y0 = sy.floor() as u32;
        let y1 = (y0 + 1).min(src_h - 1);
        let fy = sy - y0 as f32;
        for dx in 0..dst_w {
            let sx = ((dx as f32 + 0.5) * x_ratio - 0.5).max(0.0);
            let x0 = sx.floor() as u32;
            let x1 = (x0 + 1).min(src_w - 1);
            let fx = sx - x0 as f32;

            for ch in 0..3 {
                let p00 = src[((y0 * src_w + x0) * 3 + ch) as usize] as f32;
                let p10 = src[((y0 * src_w + x1) * 3 + ch) as usize] as f32;
                let p01 = src[((y1 * src_w + x0) * 3 + ch) as usize] as f32;
                let p11 = src[((y1 * src_w + x1) * 3 + ch) as usize] as f32;
                let top = p00 + (p10 - p00) * fx;
                let bottom = p01 + (p11 - p01) * fx;
                let value = top + (bottom - top) * fy;
                out[((dy * dst_w + dx) * 3 + ch) as usize] = value.round().clamp(0.0, 255.0) as u8;
            }
        }
    }
    out
}

fn iou(a: &FaceBox, b: &FaceBox) -> f32 {
    let ax2 = a.x + a.width;
    let ay2 = a.y + a.height;
    let bx2 = b.x + b.width;
    let by2 = b.y + b.height;
    let ix1 = a.x.max(b.x);
    let iy1 = a.y.max(b.y);
    let ix2 = ax2.min(bx2);
    let iy2 = ay2.min(by2);
    let iw = (ix2 - ix1).max(0.0);
    let ih = (iy2 - iy1).max(0.0);
    let intersection = iw * ih;
    let union = a.width * a.height + b.width * b.height - intersection;
    if union <= 0.0 {
        0.0
    } else {
        intersection / union
    }
}

fn non_max_suppression(boxes: Vec<FaceBox>, iou_threshold: f32) -> Vec<FaceBox> {
    let mut kept: Vec<FaceBox> = Vec::new();
    'outer: for candidate in boxes {
        for existing in &kept {
            if iou(&candidate, existing) >= iou_threshold {
                continue 'outer;
            }
        }
        kept.push(candidate);
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_box(x: f32, y: f32, w: f32, h: f32, score: f32) -> FaceBox {
        FaceBox {
            x,
            y,
            width: w,
            height: h,
            score,
            landmarks: [(0.0, 0.0); 5],
        }
    }

    #[test]
    fn iou_of_identical_boxes_is_one() {
        let a = make_box(10.0, 10.0, 20.0, 20.0, 0.9);
        let b = make_box(10.0, 10.0, 20.0, 20.0, 0.9);
        assert!((iou(&a, &b) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn iou_of_disjoint_boxes_is_zero() {
        let a = make_box(0.0, 0.0, 10.0, 10.0, 0.9);
        let b = make_box(100.0, 100.0, 10.0, 10.0, 0.9);
        assert_eq!(iou(&a, &b), 0.0);
    }

    #[test]
    fn nms_keeps_highest_scoring_of_overlapping_boxes() {
        let boxes = vec![
            make_box(0.0, 0.0, 20.0, 20.0, 0.95),
            make_box(1.0, 1.0, 20.0, 20.0, 0.80), // heavily overlaps the first
            make_box(100.0, 100.0, 20.0, 20.0, 0.70), // disjoint, survives
        ];
        let kept = non_max_suppression(boxes, 0.3);
        assert_eq!(kept.len(), 2);
        assert!((kept[0].score - 0.95).abs() < 1e-6);
        assert!((kept[1].score - 0.70).abs() < 1e-6);
    }

    #[test]
    fn bilinear_resize_preserves_uniform_color() {
        let src = vec![128u8; (4 * 4 * 3) as usize];
        let out = resize_bilinear_rgb(&src, 4, 4, 8, 8);
        assert!(out.iter().all(|&v| v == 128));
    }

    #[test]
    fn bilinear_resize_produces_requested_dimensions() {
        let src = vec![0u8; (10 * 6 * 3) as usize];
        let out = resize_bilinear_rgb(&src, 10, 6, 640, 640);
        assert_eq!(out.len(), 640 * 640 * 3);
    }
}
