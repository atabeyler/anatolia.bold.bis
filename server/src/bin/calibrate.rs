//! Threshold calibration/evaluation CLI (madde 25, extended by item 3 in
//! the newer V1-closure checklist). Reads a CSV of `score,label` pairs
//! and reports FAR/FRR at the observed thresholds, the equal-error-rate
//! point, and AUC — see `calibration.rs` for what this math does and
//! does not prove (it verifies the calibration math itself, not this
//! deployment's real-world accuracy, since no authorized labeled
//! biometric dataset exists in this environment to evaluate against).
//!
//! Usage:
//!   cargo run --bin calibrate -- pairs.csv [--format text|json|csv]
//!     [--model-name sface --model-version 2021dec --save-threshold]
//!
//! CSV input format, no header: `score,label` per line, where `label` is
//! one of `genuine`/`impostor` (or `1`/`0`) — e.g.:
//!   0.94,genuine
//!   0.12,impostor
//!
//! `--format` controls how the *results* are printed: `text` (default,
//! human-readable), `json` (machine-readable, one object), or `csv`
//! (the ROC curve as `threshold,far,frr` rows, EER/AUC as a leading
//! comment).
//!
//! `--save-threshold` (requires `--model-name`/`--model-version`) writes
//! the computed equal-error-rate threshold into the `biometric_thresholds`
//! table (`db::biometric::save_calibrated_threshold`) — the same
//! DATABASE_URL/SQLite-fallback connection logic every other binary in
//! this workspace uses — so a real calibration run's result is available
//! to the running server, not just printed to a terminal. Never called
//! automatically; a human runs this deliberately against a real,
//! authorized dataset.

use anatolia_bis_server::calibration::{auc, equal_error_rate, roc_curve, ScoredPair};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
    Csv,
}

impl OutputFormat {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "json" => Some(Self::Json),
            "csv" => Some(Self::Csv),
            _ => None,
        }
    }
}

struct Args {
    csv_path: String,
    format: OutputFormat,
    model_name: Option<String>,
    model_version: Option<String>,
    save_threshold: bool,
}

fn parse_args(raw: &[String]) -> Result<Args, String> {
    let mut csv_path = None;
    let mut format = OutputFormat::Text;
    let mut model_name = None;
    let mut model_version = None;
    let mut save_threshold = false;

    let mut iter = raw.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--format" => {
                let value = iter.next().ok_or("--format requires a value")?;
                format = OutputFormat::parse(value)
                    .ok_or_else(|| format!("unknown --format {value} (expected text|json|csv)"))?;
            }
            "--model-name" => {
                model_name = Some(iter.next().ok_or("--model-name requires a value")?.clone());
            }
            "--model-version" => {
                model_version = Some(
                    iter.next()
                        .ok_or("--model-version requires a value")?
                        .clone(),
                );
            }
            "--save-threshold" => save_threshold = true,
            other if csv_path.is_none() && !other.starts_with("--") => {
                csv_path = Some(other.to_string());
            }
            other => return Err(format!("unrecognized argument: {other}")),
        }
    }

    let csv_path = csv_path.ok_or("usage: calibrate <pairs.csv> [--format text|json|csv] [--model-name NAME --model-version VERSION --save-threshold]")?;
    if save_threshold && (model_name.is_none() || model_version.is_none()) {
        return Err("--save-threshold requires --model-name and --model-version".to_string());
    }
    Ok(Args {
        csv_path,
        format,
        model_name,
        model_version,
        save_threshold,
    })
}

fn parse_line(line: &str) -> Option<ScoredPair> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut parts = line.split(',');
    let score: f64 = parts.next()?.trim().parse().ok()?;
    let label = parts.next()?.trim().to_ascii_lowercase();
    let is_genuine = match label.as_str() {
        "genuine" | "1" | "true" | "match" => true,
        "impostor" | "0" | "false" | "nomatch" | "no_match" => false,
        _ => return None,
    };
    Some(ScoredPair { score, is_genuine })
}

fn print_text(pairs: &[ScoredPair], genuine_count: usize, impostor_count: usize) {
    println!(
        "Loaded {} pairs ({genuine_count} genuine, {impostor_count} impostor)",
        pairs.len()
    );
    if genuine_count == 0 || impostor_count == 0 {
        println!(
            "WARNING: FAR/FRR/EER/AUC are not meaningful without both genuine and impostor pairs."
        );
    }
    if let Some((threshold, rate)) = equal_error_rate(pairs) {
        println!(
            "Equal error rate: {:.4} at threshold {:.4}",
            rate, threshold
        );
    }
    println!("AUC: {:.4}", auc(pairs));
    println!("\nROC curve (threshold, FAR, FRR):");
    for point in roc_curve(pairs) {
        if point.threshold.is_finite() {
            println!(
                "  {:>8.4}  FAR={:.4}  FRR={:.4}",
                point.threshold, point.far, point.frr
            );
        }
    }
}

fn print_json(pairs: &[ScoredPair], genuine_count: usize, impostor_count: usize) {
    let eer = equal_error_rate(pairs);
    let curve: Vec<String> = roc_curve(pairs)
        .into_iter()
        .filter(|p| p.threshold.is_finite())
        .map(|p| {
            format!(
                r#"{{"threshold":{:.6},"far":{:.6},"frr":{:.6}}}"#,
                p.threshold, p.far, p.frr
            )
        })
        .collect();
    println!(
        r#"{{"pairCount":{},"genuineCount":{genuine_count},"impostorCount":{impostor_count},"equalErrorRate":{},"equalErrorThreshold":{},"auc":{:.6},"rocCurve":[{}]}}"#,
        pairs.len(),
        eer.map(|(_, rate)| format!("{rate:.6}"))
            .unwrap_or_else(|| "null".to_string()),
        eer.map(|(threshold, _)| format!("{threshold:.6}"))
            .unwrap_or_else(|| "null".to_string()),
        auc(pairs),
        curve.join(","),
    );
}

fn print_csv(pairs: &[ScoredPair]) {
    if let Some((threshold, rate)) = equal_error_rate(pairs) {
        println!(
            "# equal_error_rate={rate:.6},equal_error_threshold={threshold:.6},auc={:.6}",
            auc(pairs)
        );
    } else {
        println!("# auc={:.6}", auc(pairs));
    }
    println!("threshold,far,frr");
    for point in roc_curve(pairs) {
        if point.threshold.is_finite() {
            println!("{:.6},{:.6},{:.6}", point.threshold, point.far, point.frr);
        }
    }
}

#[tokio::main]
async fn main() {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&raw_args) {
        Ok(args) => args,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };

    let content = match std::fs::read_to_string(&args.csv_path) {
        Ok(content) => content,
        Err(err) => {
            eprintln!("failed to read {}: {err}", args.csv_path);
            std::process::exit(1);
        }
    };

    let pairs: Vec<ScoredPair> = content.lines().filter_map(parse_line).collect();
    let genuine_count = pairs.iter().filter(|p| p.is_genuine).count();
    let impostor_count = pairs.len() - genuine_count;

    if pairs.is_empty() {
        eprintln!("no valid score,label rows found in {}", args.csv_path);
        std::process::exit(1);
    }

    match args.format {
        OutputFormat::Text => print_text(&pairs, genuine_count, impostor_count),
        OutputFormat::Json => print_json(&pairs, genuine_count, impostor_count),
        OutputFormat::Csv => print_csv(&pairs),
    }

    if args.save_threshold {
        let Some((threshold, rate)) = equal_error_rate(&pairs) else {
            eprintln!("cannot save a threshold: no equal-error-rate point (empty ROC curve)");
            std::process::exit(1);
        };
        let model_name = args.model_name.expect("checked in parse_args");
        let model_version = args.model_version.expect("checked in parse_args");
        let config = anatolia_bis_server::config::Config::from_env();
        let state = match anatolia_bis_server::db::AppState::new(&config).await {
            Ok(state) => state,
            Err(err) => {
                eprintln!("failed to connect to the database: {err}");
                std::process::exit(1);
            }
        };
        match anatolia_bis_server::db::save_calibrated_threshold(
            &state.backend,
            &model_name,
            &model_version,
            threshold,
            rate,
            pairs.len() as i64,
        )
        .await
        {
            Ok(()) => eprintln!(
                "Saved threshold {threshold:.4} (EER {rate:.4}) for {model_name}/{model_version}"
            ),
            Err(err) => {
                eprintln!("failed to save threshold: {err}");
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_genuine_and_impostor_rows() {
        assert_eq!(parse_line("0.94,genuine").map(|p| p.is_genuine), Some(true));
        assert_eq!(
            parse_line("0.12,impostor").map(|p| p.is_genuine),
            Some(false)
        );
        assert_eq!(parse_line("0.5,1").map(|p| p.is_genuine), Some(true));
        assert_eq!(parse_line("0.5,0").map(|p| p.is_genuine), Some(false));
    }

    #[test]
    fn ignores_blank_and_comment_lines() {
        assert!(parse_line("").is_none());
        assert!(parse_line("   ").is_none());
        assert!(parse_line("# score,label").is_none());
    }

    #[test]
    fn rejects_malformed_rows() {
        assert!(parse_line("not-a-number,genuine").is_none());
        assert!(parse_line("0.5,unknown-label").is_none());
        assert!(parse_line("0.5").is_none());
    }

    #[test]
    fn parses_format_and_threshold_flags() {
        let args = parse_args(&[
            "pairs.csv".to_string(),
            "--format".to_string(),
            "json".to_string(),
        ])
        .unwrap();
        assert_eq!(args.csv_path, "pairs.csv");
        assert_eq!(args.format, OutputFormat::Json);
        assert!(!args.save_threshold);
    }

    #[test]
    fn save_threshold_without_model_identifiers_is_rejected() {
        let result = parse_args(&["pairs.csv".to_string(), "--save-threshold".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn save_threshold_with_model_identifiers_is_accepted() {
        let args = parse_args(&[
            "pairs.csv".to_string(),
            "--model-name".to_string(),
            "sface".to_string(),
            "--model-version".to_string(),
            "2021dec".to_string(),
            "--save-threshold".to_string(),
        ])
        .unwrap();
        assert!(args.save_threshold);
        assert_eq!(args.model_name.as_deref(), Some("sface"));
    }

    #[test]
    fn missing_csv_path_is_rejected() {
        assert!(parse_args(&[]).is_err());
    }

    #[test]
    fn unknown_flag_is_rejected() {
        assert!(parse_args(&["pairs.csv".to_string(), "--bogus".to_string()]).is_err());
    }
}
