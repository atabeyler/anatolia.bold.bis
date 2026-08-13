//! Real `WebSearchProvider`: the Tavily Search API
//! (<https://docs.tavily.com/documentation/api-reference/endpoint/search>)
//! — an official, documented REST API requiring an API key, not scraping.
//! Configured entirely from the environment: set `TAVILY_API_KEY` to enable
//! it. In addition to ordinary web results this provider asks Tavily for
//! query-related public-web images and emits those as `web_image` evidence.
//! This is text-query image discovery, not reverse-image/face matching.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::resilience::CircuitBreaker;
use super::{EvidenceItem, EvidenceItems, OsintError, WebSearchProvider};

const ENDPOINT: &str = "https://api.tavily.com/search";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_ATTEMPTS: u32 = 2;
const RETRY_DELAY: Duration = Duration::from_millis(300);
const FAILURE_THRESHOLD: u32 = 3;
const COOLDOWN: Duration = Duration::from_secs(30);
const MAX_IMAGE_RESULTS: usize = 12;

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
                search_depth: "basic",
                max_results: 10,
                include_images: true,
                include_image_descriptions: true,
            })
            .send()
            .await
            .map_err(|e| OsintError::ProviderUnavailable(e.to_string()))?;

        let status = response.status();
        let body_text = response.text().await.map_err(|e| {
            OsintError::ProviderUnavailable(format!("failed to read Tavily response: {e}"))
        })?;

        if !status.is_success() {
            let detail = body_text.trim();
            return Err(OsintError::ProviderUnavailable(if detail.is_empty() {
                format!("Tavily Search API returned {status}")
            } else {
                format!("Tavily Search API returned {status}: {detail}")
            }));
        }

        let body: TavilyResponse = serde_json::from_str(&body_text)
            .map_err(|e| OsintError::Internal(format!("failed to parse Tavily response: {e}")))?;

        let mut evidence: EvidenceItems = body
            .results
            .into_iter()
            .map(|result| EvidenceItem {
                source_type: "web_search".to_string(),
                provider_name: "tavily-web-search".to_string(),
                title: result.title,
                title_key: None,
                title_params: None,
                url: Some(result.url),
                snippet: result.content,
                details: Vec::new(),
                confidence: result.score.clamp(0.0, 1.0),
            })
            .collect();

        evidence.extend(
            body.images
                .into_iter()
                .take(MAX_IMAGE_RESULTS)
                .map(|image| EvidenceItem {
                    source_type: "web_image".to_string(),
                    provider_name: "tavily-image-search".to_string(),
                    title: image
                        .description
                        .clone()
                        .filter(|value| !value.trim().is_empty())
                        .unwrap_or_else(|| "Public web image".to_string()),
                    title_key: None,
                    title_params: None,
                    url: Some(image.url),
                    snippet: image.description,
                    details: Vec::new(),
                    confidence: 0.5,
                }),
        );

        Ok(evidence)
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
    search_depth: &'static str,
    max_results: u32,
    include_images: bool,
    include_image_descriptions: bool,
}

#[derive(Debug, Deserialize)]
struct TavilyResponse {
    #[serde(default)]
    results: Vec<TavilyResult>,
    #[serde(default)]
    images: Vec<TavilyImage>,
}

#[derive(Debug, Deserialize)]
struct TavilyResult {
    title: String,
    url: String,
    content: Option<String>,
    #[serde(default)]
    score: f64,
}

#[derive(Debug, Deserialize)]
struct TavilyImage {
    url: String,
    description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tavily_response_with_no_results_or_images_parses_as_empty() {
        let json = r#"{"query": "test"}"#;
        let parsed: TavilyResponse = serde_json::from_str(json).unwrap();
        assert!(parsed.results.is_empty());
        assert!(parsed.images.is_empty());
    }

    #[test]
    fn tavily_response_deserializes_results_and_images() {
        let json = r#"{
            "query": "test",
            "images": [
                {"url": "https://example.test/photo.jpg", "description": "Example photo"}
            ],
            "results": [
                {"title": "Example", "url": "https://example.test", "content": "A test result", "score": 0.92}
            ],
            "response_time": 0.5
        }"#;
        let parsed: TavilyResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.results.len(), 1);
        assert_eq!(parsed.images.len(), 1);
        assert_eq!(parsed.results[0].title, "Example");
        assert_eq!(parsed.images[0].url, "https://example.test/photo.jpg");
        assert!((parsed.results[0].score - 0.92).abs() < f64::EPSILON);
    }
}
