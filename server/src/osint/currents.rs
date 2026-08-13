//! Real `NewsProvider`: the Currents API `/v1/search` endpoint
//! (<https://currentsapi.services/en/docs/search>) — an official,
//! documented REST API requiring an API key, not scraping. Chosen
//! alongside `news::RealNewsProvider` (NewsAPI.org) as a lower-cost
//! alternative: NewsAPI's free tier explicitly forbids production/
//! commercial use (localhost-only CORS, 24-hour-delayed articles),
//! while Currents' free tier is documented as usable in production.
//! Configured entirely from the environment: set `CURRENTS_API_KEY` to
//! enable it. Without that variable, `EvidenceOrchestrator::from_env`
//! (see `osint/mod.rs`) falls back to `NEWS_API_KEY` if set, or
//! `MockNewsProvider` otherwise — this module is never constructed with
//! an empty key.

use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

use super::resilience::CircuitBreaker;
use super::{EvidenceItem, EvidenceItems, NewsProvider, OsintError};

const ENDPOINT: &str = "https://api.currentsapi.services/v1/search";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_ATTEMPTS: u32 = 2;
const RETRY_DELAY: Duration = Duration::from_millis(300);
const FAILURE_THRESHOLD: u32 = 3;
const COOLDOWN: Duration = Duration::from_secs(30);

pub struct CurrentsNewsProvider {
    client: reqwest::Client,
    api_key: String,
    breaker: CircuitBreaker,
}

impl CurrentsNewsProvider {
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
            .query(&[("keywords", query), ("apiKey", &self.api_key)])
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| OsintError::ProviderUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(OsintError::ProviderUnavailable(format!(
                "Currents API returned {}",
                response.status()
            )));
        }

        let body: CurrentsResponse = response
            .json()
            .await
            .map_err(|e| OsintError::Internal(format!("failed to parse response: {e}")))?;

        Ok(body
            .news
            .into_iter()
            .enumerate()
            .map(|(rank, article)| EvidenceItem {
                source_type: "news".to_string(),
                provider_name: "currents-news".to_string(),
                title: article.title,
                title_key: None,
                title_params: None,
                url: Some(article.url),
                snippet: article.description,
                details: Vec::new(),
                // Currents doesn't return a relevance score — same
                // rank-derived placeholder as `news.rs` (NewsAPI); never
                // a match/no-match signal (see
                // `EvidenceItem::confidence`'s doc comment).
                confidence: (0.85 - (rank as f64) * 0.05).clamp(0.1, 0.85),
            })
            .collect())
    }
}

#[async_trait]
impl NewsProvider for CurrentsNewsProvider {
    fn name(&self) -> &'static str {
        "currents-news"
    }

    async fn search(&self, query: &str) -> Result<Vec<EvidenceItem>, OsintError> {
        self.breaker
            .call(self.name(), MAX_ATTEMPTS, RETRY_DELAY, || self.fetch(query))
            .await
    }
}

#[derive(Debug, Deserialize)]
struct CurrentsResponse {
    #[serde(default)]
    news: Vec<CurrentsArticle>,
}

#[derive(Debug, Deserialize)]
struct CurrentsArticle {
    title: String,
    url: String,
    description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn currents_response_with_no_news_field_parses_as_empty() {
        let json = r#"{"status": "error"}"#;
        let parsed: CurrentsResponse = serde_json::from_str(json).unwrap();
        assert!(parsed.news.is_empty());
    }

    #[test]
    fn currents_response_deserializes_articles() {
        let json = r#"{
            "status": "ok",
            "news": [
                {
                    "id": "00000000-0000-0000-0000-000000000000",
                    "title": "Example article",
                    "url": "https://example.test/article",
                    "description": "A test article",
                    "author": "Example News",
                    "image": "None",
                    "category": ["general"],
                    "language": "en",
                    "published": "2026-08-10 12:00:00 +0000"
                }
            ]
        }"#;
        let parsed: CurrentsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.news.len(), 1);
        assert_eq!(parsed.news[0].title, "Example article");
    }
}
