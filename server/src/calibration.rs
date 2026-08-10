//! Biometric threshold calibration/evaluation math: real,
//! working FAR/FRR/ROC/EER/AUC computation over caller-supplied scored
//! pairs. This module cannot and does not claim to produce a real-world
//! accuracy number for this deployment's biometric provider — that would
//! require an authorized, labeled dataset of genuine (same-person) and
//! impostor (different-person) comparison pairs, and no such dataset
//! exists in this environment. What's tested and verified here is the
//! *math itself*: given a set of `(score, is_genuine)` pairs — however
//! they were produced — this computes correct FAR/FRR at any threshold,
//! a full ROC curve, the equal-error-rate threshold, and AUC. A real
//! deployment with an authorized dataset can feed real pairs through
//! `bin/calibrate.rs` (a CSV-driven CLI wrapping this module) to get a
//! real evaluation.

/// One scored comparison: `score` is the similarity the provider assigned
/// (e.g. cosine similarity in `[-1, 1]`, or `[0, 1]` for normalized
/// embeddings), `is_genuine` is ground truth — `true` if the two
/// biometric samples really are the same person, `false` if they are
/// different people.
#[derive(Debug, Clone, Copy)]
pub struct ScoredPair {
    pub score: f64,
    pub is_genuine: bool,
}

/// False Accept Rate at `threshold`: the fraction of impostor
/// (different-person) pairs whose score is at or above the threshold —
/// i.e. incorrectly accepted as a match. `0.0` if there are no impostor
/// pairs (undefined rate reported as zero rather than NaN).
pub fn far_at_threshold(pairs: &[ScoredPair], threshold: f64) -> f64 {
    let impostors: Vec<&ScoredPair> = pairs.iter().filter(|p| !p.is_genuine).collect();
    if impostors.is_empty() {
        return 0.0;
    }
    let false_accepts = impostors.iter().filter(|p| p.score >= threshold).count();
    false_accepts as f64 / impostors.len() as f64
}

/// False Reject Rate at `threshold`: the fraction of genuine
/// (same-person) pairs whose score is below the threshold — i.e.
/// incorrectly rejected as a non-match. `0.0` if there are no genuine
/// pairs.
pub fn frr_at_threshold(pairs: &[ScoredPair], threshold: f64) -> f64 {
    let genuine: Vec<&ScoredPair> = pairs.iter().filter(|p| p.is_genuine).collect();
    if genuine.is_empty() {
        return 0.0;
    }
    let false_rejects = genuine.iter().filter(|p| p.score < threshold).count();
    false_rejects as f64 / genuine.len() as f64
}

#[derive(Debug, Clone, Copy)]
pub struct RocPoint {
    pub threshold: f64,
    pub far: f64,
    pub frr: f64,
}

/// A full ROC curve: FAR/FRR evaluated at every distinct score in
/// `pairs` (plus the two extremes), sorted by threshold ascending. Using
/// the actual observed scores as thresholds (rather than an arbitrary
/// fixed grid) means the curve is exact — every actual decision boundary
/// the data can produce is represented, none are skipped or interpolated.
pub fn roc_curve(pairs: &[ScoredPair]) -> Vec<RocPoint> {
    let mut thresholds: Vec<f64> = pairs.iter().map(|p| p.score).collect();
    thresholds.push(f64::NEG_INFINITY);
    thresholds.push(f64::INFINITY);
    thresholds.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    thresholds.dedup_by(|a, b| a == b);

    thresholds
        .into_iter()
        .map(|threshold| RocPoint {
            threshold,
            far: far_at_threshold(pairs, threshold),
            frr: frr_at_threshold(pairs, threshold),
        })
        .collect()
}

/// The threshold at which FAR and FRR are closest to equal (the
/// "equal error rate" point commonly used to summarize a biometric
/// system's separability with a single number), and that shared
/// approximate rate. Returns `None` for an empty ROC curve.
pub fn equal_error_rate(pairs: &[ScoredPair]) -> Option<(f64, f64)> {
    let curve = roc_curve(pairs);
    curve
        .into_iter()
        .filter(|p| p.threshold.is_finite())
        .min_by(|a, b| {
            (a.far - a.frr)
                .abs()
                .partial_cmp(&(b.far - b.frr).abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|p| (p.threshold, (p.far + p.frr) / 2.0))
}

/// Area under the ROC curve, plotted as true-accept-rate (`1 - FRR`)
/// against FAR, via the trapezoidal rule. `1.0` is perfect separation
/// between genuine and impostor scores, `0.5` is no better than chance.
///
/// `roc_curve` is sorted by threshold *ascending*; walking it in
/// *descending*-threshold order (i.e. reversed) is what gives a
/// naturally monotonic (FAR, TPR) sequence to integrate over — as the
/// threshold relaxes from strict to lenient, both FAR and TPR can only
/// increase or stay the same. Re-sorting by FAR directly (rather than
/// relying on this natural ordering) would scramble the relative order
/// of same-FAR ties and silently under-count the area.
pub fn auc(pairs: &[ScoredPair]) -> f64 {
    let points: Vec<(f64, f64)> = roc_curve(pairs)
        .into_iter()
        .rev()
        .map(|p| (p.far, 1.0 - p.frr))
        .collect();
    let mut area = 0.0;
    for window in points.windows(2) {
        let (x0, y0) = window[0];
        let (x1, y1) = window[1];
        area += (x1 - x0) * (y0 + y1) / 2.0;
    }
    area
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(score: f64, is_genuine: bool) -> ScoredPair {
        ScoredPair { score, is_genuine }
    }

    #[test]
    fn far_counts_impostor_scores_at_or_above_threshold() {
        let pairs = vec![
            pair(0.9, false),
            pair(0.5, false),
            pair(0.2, false),
            pair(0.95, true),
        ];
        assert!((far_at_threshold(&pairs, 0.5) - (2.0 / 3.0)).abs() < 1e-9);
    }

    #[test]
    fn frr_counts_genuine_scores_below_threshold() {
        let pairs = vec![
            pair(0.9, true),
            pair(0.3, true),
            pair(0.1, true),
            pair(0.95, false),
        ];
        assert!((frr_at_threshold(&pairs, 0.5) - (2.0 / 3.0)).abs() < 1e-9);
    }

    #[test]
    fn far_and_frr_are_zero_with_no_data_of_that_class() {
        let only_genuine = vec![pair(0.9, true), pair(0.8, true)];
        assert_eq!(far_at_threshold(&only_genuine, 0.5), 0.0);
        let only_impostor = vec![pair(0.1, false), pair(0.2, false)];
        assert_eq!(frr_at_threshold(&only_impostor, 0.5), 0.0);
    }

    #[test]
    fn perfectly_separated_scores_have_zero_equal_error_rate() {
        // Every genuine score strictly higher than every impostor score:
        // a threshold exists with FAR = FRR = 0.
        let pairs = vec![
            pair(0.95, true),
            pair(0.90, true),
            pair(0.85, true),
            pair(0.40, false),
            pair(0.30, false),
            pair(0.20, false),
        ];
        let (_, rate) = equal_error_rate(&pairs).unwrap();
        assert!(rate < 1e-9, "expected ~0 EER, got {rate}");
    }

    #[test]
    fn perfectly_separated_scores_have_auc_of_one() {
        let pairs = vec![
            pair(0.95, true),
            pair(0.90, true),
            pair(0.40, false),
            pair(0.30, false),
        ];
        assert!((auc(&pairs) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn identical_score_distributions_have_high_error_and_auc_near_half() {
        // Genuine and impostor scores drawn from the exact same set:
        // no threshold separates them well.
        let pairs = vec![
            pair(0.5, true),
            pair(0.5, false),
            pair(0.6, true),
            pair(0.6, false),
            pair(0.4, true),
            pair(0.4, false),
        ];
        let area = auc(&pairs);
        assert!(
            (0.4..=0.6).contains(&area),
            "expected AUC near 0.5, got {area}"
        );
    }

    #[test]
    fn roc_curve_is_sorted_by_threshold_and_endpoints_are_finite_free() {
        let pairs = vec![pair(0.7, true), pair(0.3, false)];
        let curve = roc_curve(&pairs);
        assert!(curve.windows(2).all(|w| w[0].threshold <= w[1].threshold));
        assert_eq!(curve.first().unwrap().far, 1.0); // -inf threshold accepts everything
        assert_eq!(curve.last().unwrap().far, 0.0); // +inf threshold accepts nothing
    }
}
