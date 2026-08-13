//! Real `NewsProvider`: the NewsAPI.org `/v2/everything` endpoint
//! (<https://newsapi.org/docs/endpoints/everything>) — an official,
//! documented REST API requiring an API key, not scraping. Configured
//! entirely from the environment: set `NEWS_API_KEY` to enable it.
//! Without that variable, `EvidenceOrchestrator::from_env` (see
//! `osint/mod.rs`) falls back to `MockNewsProvider` instead.

use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

use super::resilience::CircuitBreaker;
use super::{EvidenceItem, EvidenceItems, NewsProvider, OsintError};

const ENDPOINT: &str = "https://newsapi.org/v2/everything";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_ATTEMPTS: u32 = 2;
const RETRY_DELAY: Duration = Duration::from_millis(300);
const FAILURE_THRESHOLD: u32 = 3;
const COOLDOWN: Duration = Duration::from_secs(30);

pub struct RealNewsProvider {
    client: reqwest::Client,
    api_key: String,
    breaker: CircuitBreaker,
}

impl RealNewsProvider {
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
            .query(&[("q", query), ("pageSize", "10"), ("sortBy", "relevancy")])
            .header("Accept", "application/json")
            .header("X-Api-Key", &self.api_key)
            .send()
            .await
            .map_err(|e| OsintError::ProviderUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(OsintError::ProviderUnavailable(format!(
                "NewsAPI returned {}",
                response.status()
            )));
        }

        let body: NewsApiResponse = response
            .json()
            .await
            .map_err(|e| OsintError::Internal(format!("failed to parse response: {e}")))?;

        Ok(body
            .articles
            .into_iter()
            .enumerate()
            .map(|(rank, article)| EvidenceItem {
                source_type: "news".to_string(),
                provider_name: "newsapi".to_string(),
                title: article.title,
                title_key: None,
                title_params: None,
                url: Some(article.url),
                snippet: article.description,
                details: Vec::new(),
                // Same rank-derived placeholder as `websearch.rs` — see
                // that module's comment on `confidence`.
                confidence: (0.85 - (rank as f64) * 0.05).clamp(0.1, 0.85),
            })
            .collect())
    }
}

#[async_trait]
impl NewsProvider for RealNewsProvider {
    fn name(&self) -> &'static str {
        "newsapi"
    }

    async fn search(&self, query: &str) -> Result<Vec<EvidenceItem>, OsintError> {
        self.breaker
            .call(self.name(), MAX_ATTEMPTS, RETRY_DELAY, || self.fetch(query))
            .await
    }
}

#[derive(Debug, Deserialize)]
struct NewsApiResponse {
    #[serde(default)]
    articles: Vec<NewsApiArticle>,
}

#[derive(Debug, Deserialize)]
struct NewsApiArticle {
    title: String,
    url: String,
    description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newsapi_response_deserializes_articles() {
        let json = r#"{
            "status": "ok",
            "totalResults": 1,
            "articles": [
                {"title": "Example article", "url": "https://example.test/article", "description": "A test article", "source": {"id": null, "name": "Example News"}}
            ]
        }"#;
        let parsed: NewsApiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.articles.len(), 1);
        assert_eq!(parsed.articles[0].title, "Example article");
    }

    #[test]
    fn newsapi_response_with_no_articles_field_parses_as_empty() {
        let json = r#"{"status": "error"}"#;
        let parsed: NewsApiResponse = serde_json::from_str(json).unwrap();
        assert!(parsed.articles.is_empty());
    }
}
