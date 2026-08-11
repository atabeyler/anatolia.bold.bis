//! OSINT/evidence provider abstraction: provider traits for textual web/news,
//! authorized social sources, and public-web image discovery. Real providers
//! are selected from environment configuration and each provider failure is
//! isolated from the rest of the collection pipeline.
//!
//! Text providers (Tavily/Brave and Currents/NewsAPI) never receive the probe
//! image. Public-web image discovery is a separate capability implemented by
//! Google Cloud Vision WEB_DETECTION when `GOOGLE_CLOUD_VISION_API_KEY` is
//! configured. The authorized-social slot remains mock-only until a real
//! platform connector is explicitly deployed.

pub mod currents;
pub mod google_vision;
pub mod mock;
pub mod news;
pub mod query_builder;
pub mod resilience;
pub mod tavily;
pub mod websearch;

use async_trait::async_trait;

/// Shorthand used throughout the real-provider implementations.
pub type EvidenceItems = Vec<EvidenceItem>;

/// One piece of evidence returned by a provider, before it is persisted as
/// candidate evidence or surfaced as search-level external image evidence.
#[derive(Debug, Clone)]
pub struct EvidenceItem {
    pub source_type: String,
    pub provider_name: String,
    pub title: String,
    pub url: Option<String>,
    pub snippet: Option<String>,
    /// Provider relevance/quality signal in `[0, 1]`; never an identity
    /// verdict or probability.
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

/// Real implementations of this trait must only query sources for which the
/// deployment has explicit authorization. No access-control bypass or private
/// profile scraping belongs behind this interface.
#[async_trait]
pub trait AuthorizedSocialProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn search(&self, query: &str) -> Result<Vec<EvidenceItem>, OsintError>;
}

/// A genuine image-to-public-web lookup. This is intentionally distinct from
/// `WebSearchProvider` and `NewsProvider`, which only accept text queries.
#[async_trait]
pub trait ReverseImageSearchProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn search_by_image(&self, image_bytes: &[u8]) -> Result<Vec<EvidenceItem>, OsintError>;
    async fn search_by_image_url(&self, image_url: &str) -> Result<Vec<EvidenceItem>, OsintError>;
}

/// Which textual/social sources are currently enabled. Reverse-image status is
/// exposed separately through `provider_status()` because it is not a text
/// source and needs image bytes rather than a query string.
pub trait SourceRegistry: Send + Sync {
    fn enabled_sources(&self) -> Vec<&'static str>;
}

/// One connector slot's current status.
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

/// One provider's outcome from a single collection run.
pub struct ProviderOutcome {
    pub provider_name: String,
    pub items: Vec<EvidenceItem>,
    pub error: Option<String>,
}

/// Runs configured providers while isolating failures between provider slots.
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

    /// Build the provider set from deployment environment variables.
    ///
    /// Web: `TAVILY_API_KEY`, then `BRAVE_SEARCH_API_KEY`.
    /// News: `CURRENTS_API_KEY`, then `NEWS_API_KEY`.
    /// Public-web image discovery: `GOOGLE_CLOUD_VISION_API_KEY`.
    /// Authorized social: no real connector is bundled today.
    pub fn from_env() -> Self {
        let web_search: Vec<std::sync::Arc<dyn WebSearchProvider>> =
            match (env_key("TAVILY_API_KEY"), env_key("BRAVE_SEARCH_API_KEY")) {
                (Some(key), _) => {
                    tracing::info!("OSINT: Tavily web-search provider enabled");
                    vec![std::sync::Arc::new(tavily::TavilyWebSearchProvider::new(
                        key,
                    ))]
                }
                (None, Some(key)) => {
                    tracing::info!("OSINT: Brave Search web-search provider enabled");
                    vec![std::sync::Arc::new(websearch::RealWebSearchProvider::new(
                        key,
                    ))]
                }
                (None, None) => vec![std::sync::Arc::new(mock::MockWebSearchProvider)],
            };

        let news: Vec<std::sync::Arc<dyn NewsProvider>> =
            match (env_key("CURRENTS_API_KEY"), env_key("NEWS_API_KEY")) {
                (Some(key), _) => {
                    tracing::info!("OSINT: Currents news provider enabled");
                    vec![std::sync::Arc::new(currents::CurrentsNewsProvider::new(
                        key,
                    ))]
                }
                (None, Some(key)) => {
                    tracing::info!("OSINT: NewsAPI news provider enabled");
                    vec![std::sync::Arc::new(news::RealNewsProvider::new(key))]
                }
                (None, None) => vec![std::sync::Arc::new(mock::MockNewsProvider)],
            };

        let reverse_image: Vec<std::sync::Arc<dyn ReverseImageSearchProvider>> =
            match env_key("GOOGLE_CLOUD_VISION_API_KEY") {
                Some(key) => {
                    tracing::info!("OSINT: Google Vision web-detection provider enabled");
                    vec![std::sync::Arc::new(
                        google_vision::GoogleVisionWebDetectionProvider::new(key),
                    )]
                }
                None => Vec::new(),
            };

        Self::new(
            web_search,
            news,
            vec![std::sync::Arc::new(mock::MockSocialProvider)],
            reverse_image,
        )
    }

    /// Read-only visibility into the active provider in each capability slot.
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

    /// Run every textual/social provider for a manually supplied query.
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

    /// Automatic candidate enrichment uses web search and news only. Social
    /// remains opt-in/manual until an authorized real implementation exists.
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

    /// Run public-web image discovery directly from the sanitized probe. If no
    /// provider is configured this returns an empty vector and no image leaves
    /// the application through this capability.
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
            Err(OsintError::ProviderUnavailable(
                "simulated failure".to_string(),
            ))
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
        assert_eq!(outcomes[0].provider_name, "failing-web-search");
        assert!(outcomes[0].error.is_some());
        assert!(outcomes[0].items.is_empty());
        assert!(outcomes[1].error.is_none());
        assert!(!outcomes[1].items.is_empty());
        assert!(outcomes[2].error.is_none());
        assert!(outcomes[3].error.is_none());
    }

    #[tokio::test]
    async fn mock_orchestrator_reports_every_configured_textual_source() {
        let orchestrator = EvidenceOrchestrator::mock();
        let sources = orchestrator.enabled_sources();
        assert_eq!(sources.len(), 3);
        assert_eq!(
            orchestrator
                .provider_status()
                .iter()
                .find(|status| status.slot == "reverse_image")
                .unwrap()
                .provider_name,
            "not-configured"
        );
    }

    #[tokio::test]
    async fn mock_providers_are_deterministic_for_the_same_query() {
        let orchestrator = EvidenceOrchestrator::mock();
        let first = orchestrator.collect("Jane Doe").await;
        let second = orchestrator.collect("Jane Doe").await;
        assert_eq!(first[0].items.len(), second[0].items.len());
        assert_eq!(first[0].items[0].title, second[0].items[0].title);
    }

    static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clear_osint_env_keys() {
        for key in [
            "TAVILY_API_KEY",
            "BRAVE_SEARCH_API_KEY",
            "CURRENTS_API_KEY",
            "NEWS_API_KEY",
            "GOOGLE_CLOUD_VISION_API_KEY",
        ] {
            std::env::remove_var(key);
        }
    }

    #[tokio::test]
    async fn from_env_falls_back_to_mock_text_providers_when_no_keys_are_set() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear_osint_env_keys();
        let orchestrator = EvidenceOrchestrator::from_env();
        let sources = orchestrator.enabled_sources();
        assert_eq!(sources, vec!["mock-web-search", "mock-news", "mock-social"]);
        clear_osint_env_keys();
    }

    #[tokio::test]
    async fn from_env_uses_fallback_text_providers_when_only_their_keys_are_set() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear_osint_env_keys();
        std::env::set_var("BRAVE_SEARCH_API_KEY", "test-key");
        std::env::set_var("NEWS_API_KEY", "test-key");
        let orchestrator = EvidenceOrchestrator::from_env();
        let sources = orchestrator.enabled_sources();
        assert_eq!(sources, vec!["brave-web-search", "newsapi", "mock-social"]);
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
        let sources = orchestrator.enabled_sources();
        assert_eq!(
            sources,
            vec!["tavily-web-search", "currents-news", "mock-social"]
        );
        clear_osint_env_keys();
    }

    #[tokio::test]
    async fn from_env_enables_google_vision_reverse_image_provider() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear_osint_env_keys();
        std::env::set_var("GOOGLE_CLOUD_VISION_API_KEY", "test-key");
        let orchestrator = EvidenceOrchestrator::from_env();
        let status = orchestrator.provider_status();
        let reverse = status
            .iter()
            .find(|status| status.slot == "reverse_image")
            .unwrap();
        assert_eq!(reverse.provider_name, "google-vision-web-detection");
        assert!(!reverse.is_mock);
        clear_osint_env_keys();
    }
}
