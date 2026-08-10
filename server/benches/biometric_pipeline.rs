//! Performance benchmarks (madde 44). Run with `cargo bench`.
//!
//! Scope, and what's deliberately *not* here: these benchmark the parts
//! of the pipeline that run without any external dependency (a model file
//! on disk, a live Postgres instance) — probe-image validation, template
//! vector search, and the classical-CV alignment/quality steps. Real
//! ONNX inference (YuNet detection, SFace embedding) is not benchmarked
//! here: it requires the pinned model files to be present
//! (`biometric::models::ensure_model`, which downloads them over the
//! network on first use) and this environment cannot guarantee network
//! access at benchmark time. Benchmarking it is real, valuable follow-up
//! work for a deployment that already has the models cached locally, not
//! something to fake with a synthetic stand-in for the actual ONNX
//! Runtime inference cost. A PostgreSQL-backed DB-path benchmark is
//! likewise out of scope here (this benchmark suite has no running
//! Postgres to connect to); the included DB benchmark runs against the
//! same in-memory SQLite backend the test suite uses, which is
//! representative of local-dev/CI performance, not a production
//! Postgres deployment's.

use std::hint::black_box;

use anatolia_bis_server::biometric::alignment::align_face;
use anatolia_bis_server::biometric::detection::FaceBox;
use anatolia_bis_server::biometric::quality::{check_blur_and_lighting, check_pose};
use anatolia_bis_server::db::{top_k_matches, AppState, BiometricTemplateRow};
use anatolia_bis_server::image_validation::validate_and_sanitize_probe_image;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn make_probe_jpeg(width: u32, height: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    let img = image::RgbImage::from_fn(width, height, |x, y| {
        image::Rgb([(x % 256) as u8, (y % 256) as u8, ((x + y) % 256) as u8])
    });
    image::DynamicImage::ImageRgb8(img)
        .write_to(
            &mut std::io::Cursor::new(&mut buf),
            image::ImageFormat::Jpeg,
        )
        .unwrap();
    buf
}

fn bench_probe_image_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("probe_image_validation");
    for &(w, h) in &[(640u32, 480u32), (1920, 1080), (4000, 3000)] {
        let jpeg = make_probe_jpeg(w, h);
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{w}x{h}")),
            &jpeg,
            |b, bytes| {
                b.iter(|| validate_and_sanitize_probe_image(black_box(bytes)));
            },
        );
    }
    group.finish();
}

fn synthetic_template(candidate_id: &str, dim: usize, seed: u32) -> BiometricTemplateRow {
    // A cheap, deterministic pseudo-random unit-ish vector — not claiming
    // any real embedding distribution, only exercising the same JSON
    // parse + cosine-similarity code path real templates go through.
    let embedding: Vec<f32> = (0..dim)
        .map(|i| (((seed as usize + i) * 2654435761) % 1000) as f32 / 1000.0 - 0.5)
        .collect();
    BiometricTemplateRow {
        id: format!("template-{seed}"),
        candidate_id: candidate_id.to_string(),
        model_name: "sface".to_string(),
        model_version: "2021dec".to_string(),
        embedding_dimension: dim as i32,
        embedding: serde_json::to_string(&embedding).unwrap(),
        quality_score: 0.9,
        source_reference: None,
        created_at: "now".to_string(),
        revoked_at: None,
    }
}

fn bench_vector_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("template_vector_search");
    for &count in &[100usize, 1_000, 10_000] {
        let templates: Vec<BiometricTemplateRow> = (0..count)
            .map(|i| synthetic_template(&format!("candidate-{i}"), 128, i as u32))
            .collect();
        let probe = synthetic_template("probe", 128, 999_999).embedding_vec();
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &templates,
            |b, templates| {
                b.iter(|| top_k_matches(black_box(templates), black_box(&probe), 10));
            },
        );
    }
    group.finish();
}

fn bench_alignment(c: &mut Criterion) {
    let landmarks = [
        (220.0f32, 200.0),
        (420.0, 200.0),
        (320.0, 280.0),
        (250.0, 360.0),
        (390.0, 360.0),
    ];
    c.bench_function("face_alignment_640x480", |b| {
        let src = vec![120u8; (640 * 480 * 3) as usize];
        b.iter(|| align_face(black_box(&src), 640, 480, black_box(&landmarks)));
    });
}

/// Resolution benchmark (madde 26): alignment cost as source image
/// resolution varies from a small capture up to a high-resolution one,
/// landmarks scaled proportionally so they stay inside the frame.
fn bench_alignment_across_resolutions(c: &mut Criterion) {
    let mut group = c.benchmark_group("face_alignment_by_resolution");
    for &(w, h) in &[(320u32, 240u32), (640, 480), (1920, 1080), (4000, 3000)] {
        let src = vec![120u8; (w * h * 3) as usize];
        let sx = w as f32 / 640.0;
        let sy = h as f32 / 480.0;
        let landmarks = [
            (220.0 * sx, 200.0 * sy),
            (420.0 * sx, 200.0 * sy),
            (320.0 * sx, 280.0 * sy),
            (250.0 * sx, 360.0 * sy),
            (390.0 * sx, 360.0 * sy),
        ];
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{w}x{h}")),
            &src,
            |b, src| {
                b.iter(|| align_face(black_box(src), w, h, black_box(&landmarks)));
            },
        );
    }
    group.finish();
}

fn checkerboard_112(bright: u8, dark: u8) -> Vec<u8> {
    let size = 112u32;
    let mut buf = vec![0u8; (size * size * 3) as usize];
    for y in 0..size {
        for x in 0..size {
            let value = if (x + y) % 2 == 0 { bright } else { dark };
            let idx = ((y * size + x) * 3) as usize;
            buf[idx] = value;
            buf[idx + 1] = value;
            buf[idx + 2] = value;
        }
    }
    buf
}

/// Lighting condition benchmark (madde 26): blur/lighting check cost is
/// expected to be resolution-bound, not brightness-bound, but this
/// exercises every lighting branch (too dark / normal / too bright) the
/// real search/enrollment path can hit, not just one happy-path input.
fn bench_quality_checks_by_lighting(c: &mut Criterion) {
    let mut group = c.benchmark_group("quality_check_by_lighting");
    let conditions: &[(&str, u8, u8)] = &[
        ("very_dark", 20, 5),
        ("normal", 200, 60),
        ("very_bright", 250, 235),
    ];
    for &(label, bright, dark) in conditions {
        let buf = checkerboard_112(bright, dark);
        group.bench_with_input(BenchmarkId::from_parameter(label), &buf, |b, buf| {
            b.iter(|| check_blur_and_lighting(black_box(buf), 112));
        });
    }
    group.finish();
}

fn face_box_with_pose(right_eye_x: f32, left_eye_x: f32) -> FaceBox {
    FaceBox {
        x: 0.0,
        y: 0.0,
        width: 200.0,
        height: 200.0,
        score: 0.95,
        landmarks: [
            (right_eye_x, 40.0),
            (left_eye_x, 40.0),
            (50.0, 60.0),
            (35.0, 80.0),
            (65.0, 80.0),
        ],
    }
}

/// Pose condition benchmark (madde 26): frontal vs. increasingly rotated
/// synthetic landmark geometry through the same coarse pose check a real
/// search/enrollment probe goes through.
fn bench_pose_check_by_angle(c: &mut Criterion) {
    let mut group = c.benchmark_group("pose_check_by_angle");
    let conditions: &[(&str, f32, f32)] = &[
        ("frontal", 30.0, 70.0),
        ("mild_yaw", 40.0, 75.0),
        ("severe_yaw", 48.0, 95.0),
    ];
    for &(label, right_eye_x, left_eye_x) in conditions {
        let face = face_box_with_pose(right_eye_x, left_eye_x);
        group.bench_with_input(BenchmarkId::from_parameter(label), &face, |b, face| {
            b.iter(|| check_pose(black_box(face)));
        });
    }
    group.finish();
}

fn bench_db_list_candidates(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let state = runtime.block_on(AppState::for_tests());
    c.bench_function("db_list_candidates_sqlite_in_memory", |b| {
        b.to_async(&runtime)
            .iter(|| async { anatolia_bis_server::db::list_candidates(&state.backend).await });
    });
}

criterion_group!(
    benches,
    bench_probe_image_validation,
    bench_vector_search,
    bench_alignment,
    bench_alignment_across_resolutions,
    bench_quality_checks_by_lighting,
    bench_pose_check_by_angle,
    bench_db_list_candidates,
);
criterion_main!(benches);
