//! OSINT/evidence provider abstraction for textual web/news sources,
//! authorized social sources, and direct public-web reverse-image discovery.
//!
//! Text providers (Tavily/Brave and Currents/NewsAPI) never receive the probe
//! image. Reverse-image providers receive the sanitized probe itself and search
//! for the same or modified image on the public web. This is image matching,
//! not biometric identity matching.

pub mod currents;
pub mod google_vision;
pub mod mock;
pub mod news;
pub mod query_builder;
pub mod resilience;
pub mod tavily;
pub mod tineye;
pub mod websearch;

use async_trait::async_trait;

pub type EvidenceItems = Vec<EvidenceItem>;

#[derive(Debug, Clone)]
pub struct EvidenceItem {
    pub source_type: String,
    pub provider_name: String,
    pub title: String,
    pub url: Option<String>,
    pub snippet: Option<String>,
    /// Provider ranking/relevance signal in `[0, 1]`; never an identity verdict.
    pub confidence: f64,
}

#[derive(Debug)]
pub enum OsintError {
    ProviderUnavailable(String),
    Internal(String),
}

impl OsintError {
    pub fn code(&self) -> &'static str {
        match self {
            OsintError::ProviderUnavailable(_) => "OSINT_PROVIDER_UNAVAILABLE",
            OsintError::Internal(_) => "INTERNAL_ERROR",
        }
    }
}

impl std::fmt::Display for OsintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsintError::ProviderUnavailable(msg) => write!(f, "provider unavailable: {msg}"),
            OsintError::Internal(msg) => write!(f, "internal OSINT error: {msg}"),
        }
    }
}

impl std::error::Error for OsintError {}

#[async_trait]
pub trait WebSearchProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn search(&self, query: &str) -> Result<Vec<EvidenceItem>, OsintError>;
}

#[async_trait]
pub trait NewsProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn search(&self, query: &str) -> Result<Vec<EvidenceItem>, OsintError>;
}

#[async_trait]
pub trait AuthorizedSocialProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn search(&self, query: &str) -> Result<Vec<EvidenceItem>, OsintError>;
}

#[async_trait]
pub trait ReverseImageSearchProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn search_by_image(&self, image_bytes: &[u8]) -> Result<Vec<EvidenceItem>, OsintError>;
    async fn search_by_image_url(&self, image_url: &str) -> Result<Vec<EvidenceItem>, OsintError>;
}

pub trait SourceRegistry: Send + Sync {
    fn enabled_sources(&self) -> Vec<&'static str>;
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorStatus {
    pub slot: &'static str,
    pub provider_name: &'static str,
    pub is_mock: bool,
}

impl ConnectorStatus {
    fn new(slot: &'static str, provider_name: &'static str) -> Self {
        Self {
            slot,
            provider_name,
            is_mock: provider_name.starts_with("mock-"),
        }
    }
}

pub struct ProviderOutcome {
    pub provider_name: String,
    pub items: Vec<EvidenceItem>,
    pub error: Option<String>,
}

pub struct EvidenceOrchestrator {
    web_search: Vec<std::sync::Arc<dyn WebSearchProvider>>,
    news: Vec<std::sync::Arc<dyn NewsProvider>>,
    social: Vec<std::sync::Arc<dyn AuthorizedSocialProvider>>,
    reverse_image: Vec<std::sync::Arc<dyn ReverseImageSearchProvider>>,
}

fn env_key(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|key| !key.trim().is_empty())
}

impl EvidenceOrchestrator {
    pub fn new(
        web_search: Vec<std::sync::Arc<dyn WebSearchProvider>>,
        news: Vec<std::sync::Arc<dyn NewsProvider>>,
        social: Vec<std::sync::Arc<dyn AuthorizedSocialProvider>>,
        reverse_image: Vec<std::sync::Arc<dyn ReverseImageSearchProvider>>,
    ) -> Self {
        Self {
            web_search,
            news,
            social,
            reverse_image,
        }
    }

    pub fn mock() -> Self {
        Self::new(
            vec![std::sync::Arc::new(mock::MockWebSearchProvider)],
            vec![std::sync::Arc::new(mock::MockNewsProvider)],
            vec![std::sync::Arc::new(mock::MockSocialProvider)],
            Vec::new(),
        )
    }

    /// Build providers from deployment environment variables.
    ///
    /// Web: `TAVILY_API_KEY`, then `BRAVE_SEARCH_API_KEY`.
    /// News: `CURRENTS_API_KEY`, then `NEWS_API_KEY`.
    /// Reverse image: every configured direct provider is enabled:
    /// `TINEYE_API_KEY` and/or `GOOGLE_CLOUD_VISION_API_KEY`.
    pub fn from_env() -> Self {
        let web_search: Vec<std::sync::Arc<dyn WebSearchProvider>> =
            match (env_key("TAVILY_API_KEY"), env_key("BRAVE_SEARCH_API_KEY")) {
                (Some(key), _) => {
                    tracing::info!("OSINT: Tavily web-search provider enabled");
                    vec![std::sync::Arc::new(tavily::TavilyWebSearchProvider::new(key))]
                }
                (None, Some(key)) => {
                    tracing::info!("OSINT: Brave Search web-search provider enabled");
                    vec![std::sync::Arc::new(websearch::RealWebSearchProvider::new(key))]
                }
                (None, None) => vec![std::sync::Arc::new(mock::MockWebSearchProvider)],
            };

        let news: Vec<std::sync::Arc<dyn NewsProvider>> =
            match (env_key("CURRENTS_API_KEY"), env_key("NEWS_API_KEY")) {
                (Some(key), _) => {
                    tracing::info!("OSINT: Currents news provider enabled");
                    vec![std::sync::Arc::new(currents::CurrentsNewsProvider::new(key))]
                }
                (None, Some(key)) => {
                    tracing::info!("OSINT: NewsAPI news provider enabled");
                    vec![std::sync::Arc::new(news::RealNewsProvider::new(key))]
                }
                (None, None) => vec![std::sync::Arc::new(mock::MockNewsProvider)],
            };

        let mut reverse_image: Vec<std::sync::Arc<dyn ReverseImageSearchProvider>> = Vec::new();
        if let Some(key) = env_key("TINEYE_API_KEY") {
            tracing::info!("OSINT: TinEye reverse-image provider enabled");
            reverse_image.push(std::sync::Arc::new(
                tineye::TinEyeReverseImageProvider::new(key),
            ));
        }
        if let Some(key) = env_key("GOOGLE_CLOUD_VISION_API_KEY") {
            tracing::info!("OSINT: Google Vision web-detection provider enabled");
            reverse_image.push(std::sync::Arc::new(
                google_vision::GoogleVisionWebDetectionProvider::new(key),
            ));
        }

        Self::new(
            web_search,
            news,
            vec![std::sync::Arc::new(mock::MockSocialProvider)],
            reverse_image,
        )
    }

    pub fn provider_status(&self) -> Vec<ConnectorStatus> {
        let mut statuses = Vec::new();
        for provider in &self.web_search {
            statuses.push(ConnectorStatus::new("web_search", provider.name()));
        }
        for provider in &self.news {
            statuses.push(ConnectorStatus::new("news", provider.name()));
        }
        for provider in &self.social {
            statuses.push(ConnectorStatus::new("social", provider.name()));
        }
        if self.reverse_image.is_empty() {
            statuses.push(ConnectorStatus {
                slot: "reverse_image",
                provider_name: "not-configured",
                is_mock: false,
            });
        } else {
            for provider in &self.reverse_image {
                statuses.push(ConnectorStatus::new("reverse_image", provider.name()));
            }
        }
        statuses
    }

    pub async fn collect(&self, query: &str) -> Vec<ProviderOutcome> {
        let mut outcomes = Vec::new();
        for provider in &self.web_search {
            outcomes.push(run_provider(provider.name(), provider.search(query).await));
        }
        for provider in &self.news {
            outcomes.push(run_provider(provider.name(), provider.search(query).await));
        }
        for provider in &self.social {
            outcomes.push(run_provider(provider.name(), provider.search(query).await));
        }
        outcomes
    }

    pub async fn collect_web_and_news(
        &self,
        query: &str,
    ) -> (Vec<ProviderOutcome>, Vec<ProviderOutcome>) {
        let mut web = Vec::new();
        for provider in &self.web_search {
            web.push(run_provider(provider.name(), provider.search(query).await));
        }
        let mut news = Vec::new();
        for provider in &self.news {
            news.push(run_provider(provider.name(), provider.search(query).await));
        }
        (web, news)
    }

    /// Search the public web directly with the sanitized probe image. This
    /// runs independently of the internal biometric candidate repository.
    pub async fn collect_reverse_image(&self, image_bytes: &[u8]) -> Vec<ProviderOutcome> {
        let mut outcomes = Vec::new();
        for provider in &self.reverse_image {
            outcomes.push(run_provider(
                provider.name(),
                provider.search_by_image(image_bytes).await,
            ));
        }
        outcomes
    }
}

fn run_provider(
    provider_name: &str,
    result: Result<Vec<EvidenceItem>, OsintError>,
) -> ProviderOutcome {
    match result {
        Ok(items) => {
            metrics::counter!(
                "osint_provider_outcomes_total",
                "provider" => provider_name.to_string(),
                "outcome" => "success",
            )
            .increment(1);
            ProviderOutcome {
                provider_name: provider_name.to_string(),
                items,
                error: None,
            }
        }
        Err(err) => {
            metrics::counter!(
                "osint_provider_outcomes_total",
                "provider" => provider_name.to_string(),
                "outcome" => "failure",
            )
            .increment(1);
            tracing::warn!(provider = provider_name, error = %err, "OSINT provider failed");
            ProviderOutcome {
                provider_name: provider_name.to_string(),
                items: Vec::new(),
                error: Some(err.to_string()),
            }
        }
    }
}

impl SourceRegistry for EvidenceOrchestrator {
    fn enabled_sources(&self) -> Vec<&'static str> {
        let mut sources = Vec::new();
        for provider in &self.web_search {
            sources.push(provider.name());
        }
        for provider in &self.news {
            sources.push(provider.name());
        }
        for provider in &self.social {
            sources.push(provider.name());
        }
        sources
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingProvider;

    #[async_trait]
    impl WebSearchProvider for FailingProvider {
        fn name(&self) -> &'static str {
            "failing-web-search"
        }

        async fn search(&self, _query: &str) -> Result<Vec<EvidenceItem>, OsintError> {
            Err(OsintError::ProviderUnavailable("simulated failure".to_string()))
        }
    }

    static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clear_osint_env_keys() {
        for key in [
            "TAVILY_API_KEY",
            "BRAVE_SEARCH_API_KEY",
            "CURRENTS_API_KEY",
            "NEWS_API_KEY",
            "TINEYE_API_KEY",
            "GOOGLE_CLOUD_VISION_API_KEY",
        ] {
            std::env::remove_var(key);
        }
    }

    #[tokio::test]
    async fn one_failing_provider_does_not_prevent_others_from_reporting() {
        let orchestrator = EvidenceOrchestrator::new(
            vec![
                std::sync::Arc::new(FailingProvider),
                std::sync::Arc::new(mock::MockWebSearchProvider),
            ],
            vec![std::sync::Arc::new(mock::MockNewsProvider)],
            vec![std::sync::Arc::new(mock::MockSocialProvider)],
            Vec::new(),
        );
        let outcomes = orchestrator.collect("test query").await;
        assert_eq!(outcomes.len(), 4);
        assert!(outcomes[0].error.is_some());
        assert!(outcomes[1].error.is_none());
    }

    #[tokio::test]
    async fn from_env_falls_back_to_mock_text_providers_when_no_keys_are_set() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear_osint_env_keys();
        let orchestrator = EvidenceOrchestrator::from_env();
        assert_eq!(
            orchestrator.enabled_sources(),
            vec!["mock-web-search", "mock-news", "mock-social"]
        );
        assert_eq!(
            orchestrator
                .provider_status()
                .iter()
                .find(|status| status.slot == "reverse_image")
                .unwrap()
                .provider_name,
            "not-configured"
        );
        clear_osint_env_keys();
    }

    #[tokio::test]
    async fn from_env_prefers_tavily_and_currents_over_fallback_keys() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear_osint_env_keys();
        std::env::set_var("TAVILY_API_KEY", "test-key");
        std::env::set_var("BRAVE_SEARCH_API_KEY", "test-key");
        std::env::set_var("CURRENTS_API_KEY", "test-key");
        std::env::set_var("NEWS_API_KEY", "test-key");
        let orchestrator = EvidenceOrchestrator::from_env();
        assert_eq!(
            orchestrator.enabled_sources(),
            vec!["tavily-web-search", "currents-news", "mock-social"]
        );
        clear_osint_env_keys();
    }

    #[tokio::test]
    async fn from_env_enables_tineye_reverse_image_provider() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear_osint_env_keys();
        std::env::set_var("TINEYE_API_KEY", "test-key");
        let orchestrator = EvidenceOrchestrator::from_env();
        let status = orchestrator.provider_status();
        let reverse = status
            .iter()
            .find(|status| status.slot == "reverse_image")
            .unwrap();
        assert_eq!(reverse.provider_name, "tineye-reverse-image");
        assert!(!reverse.is_mock);
        clear_osint_env_keys();
    }
}
