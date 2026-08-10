//! Real `WebSearchProvider`: the Tavily Search API
//! (<https://docs.tavily.com/documentation/api-reference/endpoint/search>)
//! — an official, documented REST API requiring an API key, not scraping.
//! Chosen alongside `websearch::RealWebSearchProvider` (Brave) as a
//! lower-cost alternative: Tavily's free tier does not require a payment
//! method at signup, unlike Brave's. Configured entirely from the
//! environment: set `TAVILY_API_KEY` to enable it. Without that variable,
//! `EvidenceOrchestrator::from_env` (see `osint/mod.rs`) falls back to
//! `BRAVE_SEARCH_API_KEY` if set, or `MockWebSearchProvider` otherwise —
//! this module is never constructed with an empty key.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::resilience::CircuitBreaker;
use super::{EvidenceItem, EvidenceItems, OsintError, WebSearchProvider};

const ENDPOINT: &str = "https://api.tavily.com/search";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_ATTEMPTS: u32 = 2;
const RETRY_DELAY: Duration = Duration::from_millis(300);
/// Consecutive failures before the circuit opens.
const FAILURE_THRESHOLD: u32 = 3;
const COOLDOWN: Duration = Duration::from_secs(30);

pub struct TavilyWebSearchProvider {
    client: reqwest::Client,
    api_key: String,
    breaker: CircuitBreaker,
}

impl TavilyWebSearchProvider {
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
            .post(ENDPOINT)
            .bearer_auth(&self.api_key)
            .json(&TavilyRequest {
                query,
                max_results: 10,
            })
            .send()
            .await
            .map_err(|e| OsintError::ProviderUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(OsintError::ProviderUnavailable(format!(
                "Tavily Search API returned {}",
                response.status()
            )));
        }

        let body: TavilyResponse = response
            .json()
            .await
            .map_err(|e| OsintError::Internal(format!("failed to parse response: {e}")))?;

        Ok(body
            .results
            .into_iter()
            .map(|result| EvidenceItem {
                source_type: "web_search".to_string(),
                provider_name: "tavily-web-search".to_string(),
                title: result.title,
                url: Some(result.url),
                snippet: result.content,
                // Tavily's own relevance score, already in [0, 1] — unlike
                // Brave (see websearch.rs), a real per-result signal rather
                // than a rank-derived placeholder; still never treated as a
                // match/no-match verdict, only a display/sort hint (see
                // `EvidenceItem::confidence`'s doc comment).
                confidence: result.score.clamp(0.0, 1.0),
            })
            .collect())
    }
}

#[async_trait]
impl WebSearchProvider for TavilyWebSearchProvider {
    fn name(&self) -> &'static str {
        "tavily-web-search"
    }

    async fn search(&self, query: &str) -> Result<Vec<EvidenceItem>, OsintError> {
        self.breaker
            .call(self.name(), MAX_ATTEMPTS, RETRY_DELAY, || self.fetch(query))
            .await
    }
}

#[derive(Debug, Serialize)]
struct TavilyRequest<'a> {
    query: &'a str,
    max_results: u32,
}

#[derive(Debug, Deserialize)]
struct TavilyResponse {
    #[serde(default)]
    results: Vec<TavilyResult>,
}

#[derive(Debug, Deserialize)]
struct TavilyResult {
    title: String,
    url: String,
    content: Option<String>,
    #[serde(default)]
    score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tavily_response_with_no_results_field_parses_as_empty() {
        let json = r#"{"query": "test"}"#;
        let parsed: TavilyResponse = serde_json::from_str(json).unwrap();
        assert!(parsed.results.is_empty());
    }

    #[test]
    fn tavily_response_deserializes_results() {
        let json = r#"{
            "query": "test",
            "results": [
                {"title": "Example", "url": "https://example.test", "content": "A test result", "score": 0.92}
            ],
            "response_time": 0.5
        }"#;
        let parsed: TavilyResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.results.len(), 1);
        assert_eq!(parsed.results[0].title, "Example");
        assert!((parsed.results[0].score - 0.92).abs() < f64::EPSILON);
    }
}
