//! Real `WebSearchProvider`: the Brave Search API
//! (<https://api.search.brave.com/app/documentation/web-search>) — an
//! official, documented REST API requiring a subscription token, not
//! scraping. Configured entirely from the environment: set
//! `BRAVE_SEARCH_API_KEY` to enable it. Without that variable,
//! `EvidenceOrchestrator::from_env` (see `osint/mod.rs`) falls back to
//! `MockWebSearchProvider` instead — this module is never constructed
//! with an empty key.

use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

use super::resilience::CircuitBreaker;
use super::{EvidenceItem, EvidenceItems, OsintError, WebSearchProvider};

const ENDPOINT: &str = "https://api.search.brave.com/res/v1/web/search";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_ATTEMPTS: u32 = 2;
const RETRY_DELAY: Duration = Duration::from_millis(300);
/// Consecutive failures before the circuit opens.
const FAILURE_THRESHOLD: u32 = 3;
const COOLDOWN: Duration = Duration::from_secs(30);

pub struct RealWebSearchProvider {
    client: reqwest::Client,
    api_key: String,
    breaker: CircuitBreaker,
}

impl RealWebSearchProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("failed to build HTTP client"),
            api_key,
            breaker: CircuitBreaker::new(FAILURE_THRESHOLD, COOLDOWN),
        }
    }

    async fn fetch(&self, query: &str) -> Result<EvidenceItems, OsintError> {
        let response = self
            .client
            .get(ENDPOINT)
            .query(&[("q", query), ("count", "10")])
            .header("Accept", "application/json")
            .header("X-Subscription-Token", &self.api_key)
            .send()
            .await
            .map_err(|e| OsintError::ProviderUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(OsintError::ProviderUnavailable(format!(
                "Brave Search API returned {}",
                response.status()
            )));
        }

        let body: BraveResponse = response
            .json()
            .await
            .map_err(|e| OsintError::Internal(format!("failed to parse response: {e}")))?;

        let results = body.web.map(|w| w.results).unwrap_or_default();
        Ok(results
            .into_iter()
            .enumerate()
            .map(|(rank, result)| EvidenceItem {
                source_type: "web_search".to_string(),
                provider_name: "brave-web-search".to_string(),
                title: result.title,
                title_key: None,
                title_params: None,
                url: Some(result.url),
                snippet: result.description,
                details: Vec::new(),
                // Not a calibrated relevance score — Brave doesn't return
                // one — only a rank-derived placeholder so earlier results
                // sort first if items from several providers are merged;
                // never treated as a match/no-match signal (see
                // `EvidenceItem::confidence`'s doc comment).
                confidence: (0.85 - (rank as f64) * 0.05).clamp(0.1, 0.85),
            })
            .collect())
    }
}

#[async_trait]
impl WebSearchProvider for RealWebSearchProvider {
    fn name(&self) -> &'static str {
        "brave-web-search"
    }

    async fn search(&self, query: &str) -> Result<Vec<EvidenceItem>, OsintError> {
        self.breaker
            .call(self.name(), MAX_ATTEMPTS, RETRY_DELAY, || self.fetch(query))
            .await
    }
}

#[derive(Debug, Deserialize)]
struct BraveResponse {
    web: Option<BraveWebResults>,
}

#[derive(Debug, Deserialize)]
struct BraveWebResults {
    #[serde(default)]
    results: Vec<BraveResult>,
}

#[derive(Debug, Deserialize)]
struct BraveResult {
    title: String,
    url: String,
    description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_decreases_with_rank_and_stays_in_bounds() {
        let scores: Vec<f64> = (0..20)
            .map(|rank| (0.85 - (rank as f64) * 0.05).clamp(0.1, 0.85))
            .collect();
        for window in scores.windows(2) {
            assert!(window[0] >= window[1]);
        }
        for score in scores {
            assert!((0.0..=1.0).contains(&score));
        }
    }

    #[test]
    fn brave_response_with_no_web_field_parses_as_empty() {
        let json = r#"{}"#;
        let parsed: BraveResponse = serde_json::from_str(json).unwrap();
        assert!(parsed.web.is_none());
    }

    #[test]
    fn brave_response_deserializes_results() {
        let json = r#"{
            "web": {
                "results": [
                    {"title": "Example", "url": "https://example.test", "description": "A test result"}
                ]
            }
        }"#;
        let parsed: BraveResponse = serde_json::from_str(json).unwrap();
        let results = parsed.web.unwrap().results;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "Example");
    }
}
