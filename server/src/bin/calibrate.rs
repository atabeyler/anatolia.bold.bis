//! Threshold calibration/evaluation CLI (madde 25). Reads a CSV of
//! `score,label` pairs and reports FAR/FRR at the observed thresholds,
//! the equal-error-rate point, and AUC — see `calibration.rs` for what
//! this math does and does not prove (it verifies the calibration math
//! itself, not this deployment's real-world accuracy, since no
//! authorized labeled biometric dataset exists in this environment to
//! evaluate against).
//!
//! Usage:
//!   cargo run --bin calibrate -- pairs.csv
//!
//! CSV format, no header: `score,label` per line, where `label` is one
//! of `genuine`/`impostor` (or `1`/`0`) — e.g.:
//!   0.94,genuine
//!   0.12,impostor

use anatolia_bis_server::calibration::{auc, equal_error_rate, roc_curve, ScoredPair};

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

fn main() {
    let path = match std::env::args().nth(1) {
        Some(path) => path,
        None => {
            eprintln!("usage: calibrate <pairs.csv>");
            std::process::exit(2);
        }
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(err) => {
            eprintln!("failed to read {path}: {err}");
            std::process::exit(1);
        }
    };

    let pairs: Vec<ScoredPair> = content.lines().filter_map(parse_line).collect();
    let genuine_count = pairs.iter().filter(|p| p.is_genuine).count();
    let impostor_count = pairs.len() - genuine_count;

    if pairs.is_empty() {
        eprintln!("no valid score,label rows found in {path}");
        std::process::exit(1);
    }

    println!(
        "Loaded {} pairs ({genuine_count} genuine, {impostor_count} impostor)",
        pairs.len()
    );
    if genuine_count == 0 || impostor_count == 0 {
        println!(
            "WARNING: FAR/FRR/EER/AUC are not meaningful without both genuine and impostor pairs."
        );
    }

    if let Some((threshold, rate)) = equal_error_rate(&pairs) {
        println!(
            "Equal error rate: {:.4} at threshold {:.4}",
            rate, threshold
        );
    }
    println!("AUC: {:.4}", auc(&pairs));

    println!("\nROC curve (threshold, FAR, FRR):");
    for point in roc_curve(&pairs) {
        if point.threshold.is_finite() {
            println!(
                "  {:>8.4}  FAR={:.4}  FRR={:.4}",
                point.threshold, point.far, point.frr
            );
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
}
