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
use anatolia_bis_server::biometric::quality::check_blur_and_lighting;
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
    let src = vec![120u8; (640 * 480 * 3) as usize];
    let landmarks = [
        (220.0f32, 200.0),
        (420.0, 200.0),
        (320.0, 280.0),
        (250.0, 360.0),
        (390.0, 360.0),
    ];
    c.bench_function("face_alignment_640x480", |b| {
        b.iter(|| align_face(black_box(&src), 640, 480, black_box(&landmarks)));
    });
}

fn bench_quality_checks(c: &mut Criterion) {
    let size = 112u32;
    let mut buf = vec![0u8; (size * size * 3) as usize];
    for y in 0..size {
        for x in 0..size {
            let value = if (x + y) % 2 == 0 { 200u8 } else { 60u8 };
            let idx = ((y * size + x) * 3) as usize;
            buf[idx] = value;
            buf[idx + 1] = value;
            buf[idx + 2] = value;
        }
    }
    c.bench_function("blur_and_lighting_check_112x112", |b| {
        b.iter(|| check_blur_and_lighting(black_box(&buf), size));
    });
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
    bench_quality_checks,
    bench_db_list_candidates,
);
criterion_main!(benches);
