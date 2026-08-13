//! Mock OSINT providers: deterministic, content-seeded results with no
//! real external request — this environment has no authorized OSINT API
//! access, so there is nothing genuine to call. Mirrors
//! `biometric::MockBiometricProvider`'s honesty guarantee: the mock never
//! pretends to be a real source, and its items are clearly synthetic.

use async_trait::async_trait;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use super::{AuthorizedSocialProvider, EvidenceItem, NewsProvider, OsintError, WebSearchProvider};

fn deterministic_confidence(seed: &str) -> f64 {
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    let bucket = hasher.finish() % 5001; // 0..=5000
    0.30 + (bucket as f64) / 10000.0 // 0.30..=0.80
}

pub struct MockWebSearchProvider;

#[async_trait]
impl WebSearchProvider for MockWebSearchProvider {
    fn name(&self) -> &'static str {
        "mock-web-search"
    }

    async fn search(&self, query: &str) -> Result<Vec<EvidenceItem>, OsintError> {
        Ok(vec![EvidenceItem {
            source_type: "web_search".to_string(),
            provider_name: self.name().to_string(),
            title: format!("Mock web result for \"{query}\""),
            url: Some("https://example.test/mock-web-result".to_string()),
            title_key: None,
            title_params: None,
            snippet: Some(
                "This is a synthetic result from MockWebSearchProvider — no real web search was performed.".to_string(),
            ),
            details: Vec::new(),
            confidence: deterministic_confidence(&format!("web:{query}")),
        }])
    }
}

pub struct MockNewsProvider;

#[async_trait]
impl NewsProvider for MockNewsProvider {
    fn name(&self) -> &'static str {
        "mock-news"
    }

    async fn search(&self, query: &str) -> Result<Vec<EvidenceItem>, OsintError> {
        Ok(vec![EvidenceItem {
            source_type: "news".to_string(),
            provider_name: self.name().to_string(),
            title: format!("Mock news article for \"{query}\""),
            url: Some("https://example.test/mock-news-result".to_string()),
            title_key: None,
            title_params: None,
            snippet: Some(
                "This is a synthetic result from MockNewsProvider — no real news search was performed.".to_string(),
            ),
            details: Vec::new(),
            confidence: deterministic_confidence(&format!("news:{query}")),
        }])
    }
}

pub struct MockSocialProvider;

#[async_trait]
impl AuthorizedSocialProvider for MockSocialProvider {
    fn name(&self) -> &'static str {
        "mock-social"
    }

    async fn search(&self, query: &str) -> Result<Vec<EvidenceItem>, OsintError> {
        Ok(vec![EvidenceItem {
            source_type: "social".to_string(),
            provider_name: self.name().to_string(),
            title: format!("Mock social profile match for \"{query}\""),
            url: None,
            title_key: None,
            title_params: None,
            snippet: Some(
                "This is a synthetic result from MockSocialProvider — no real, authorized social platform was queried.".to_string(),
            ),
            details: Vec::new(),
            confidence: deterministic_confidence(&format!("social:{query}")),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn web_search_result_is_deterministic() {
        let provider = MockWebSearchProvider;
        let first = provider.search("Alice").await.unwrap();
        let second = provider.search("Alice").await.unwrap();
        assert_eq!(first[0].confidence, second[0].confidence);
    }

    #[tokio::test]
    async fn different_queries_score_differently() {
        let provider = MockWebSearchProvider;
        let a = provider.search("Alice").await.unwrap();
        let b = provider.search("Bob").await.unwrap();
        assert_ne!(a[0].confidence, b[0].confidence);
    }

    #[tokio::test]
    async fn confidence_is_within_bounds() {
        for query in ["Alice", "Bob", "Charlie", ""] {
            let web = MockWebSearchProvider.search(query).await.unwrap();
            let news = MockNewsProvider.search(query).await.unwrap();
            let social = MockSocialProvider.search(query).await.unwrap();
            for item in web.iter().chain(news.iter()).chain(social.iter()) {
                assert!(item.confidence >= 0.0 && item.confidence <= 1.0);
            }
        }
    }
}
