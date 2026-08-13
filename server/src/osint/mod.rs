//! OSINT/evidence provider abstraction for textual web/news sources,
//! authorized social sources, and direct public-web reverse-image discovery.
//!
//! Text providers never receive the probe image. Reverse-image providers receive
//! the sanitized probe itself and search for the same or modified image on the
//! public web. This is image matching, not biometric identity matching.

pub mod currents;
pub mod google_vision;
pub mod mock;
pub mod news;
pub mod query_builder;
pub mod resilience;
pub mod tavily;
pub mod tineye;
pub mod websearch;
pub mod yandex_images;

use async_trait::async_trait;

pub type EvidenceItems = Vec<EvidenceItem>;

/// An app-generated (not source-provided) evidence label, expressed as an
/// i18n key plus its interpolation parameters rather than pre-rendered
/// English text, so the client can render it in the viewer's language.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EvidenceDetail {
    pub key: String,
    pub params: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct EvidenceItem {
    pub source_type: String,
    pub provider_name: String,
    /// The item's own natural-language title as reported by the source
    /// (a real page title, article headline, etc.) — external content,
    /// not translated. Empty when the source provided none; use
    /// `title_key` in that case instead.
    pub title: String,
    /// Set only when `title` is empty and this item's label was generated
    /// by this application (e.g. "Full matching image") rather than
    /// sourced from the provider, so the client can render it via i18n.
    pub title_key: Option<String>,
    pub title_params: Option<serde_json::Value>,
    pub url: Option<String>,
    pub snippet: Option<String>,
    /// App-generated supplementary facts (match counts, scores, matched
    /// image URL, crawl date, ...), each an i18n key with parameters
    /// rather than pre-formatted English text.
    pub details: Vec<EvidenceDetail>,
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

    /// Build every configured provider from deployment environment variables.
    /// No real provider suppresses another provider in the same evidence class.
    /// Mock text providers are used only when that class has no real provider.
    pub fn from_env() -> Self {
        let mut web_search: Vec<std::sync::Arc<dyn WebSearchProvider>> = Vec::new();
        if let Some(key) = env_key("TAVILY_API_KEY") {
            tracing::info!("OSINT: Tavily web-search provider enabled");
            web_search.push(std::sync::Arc::new(tavily::TavilyWebSearchProvider::new(
                key,
            )));
        }
        if let Some(key) = env_key("BRAVE_SEARCH_API_KEY") {
            tracing::info!("OSINT: Brave Search web-search provider enabled");
            web_search.push(std::sync::Arc::new(websearch::RealWebSearchProvider::new(
                key,
            )));
        }
        if web_search.is_empty() {
            web_search.push(std::sync::Arc::new(mock::MockWebSearchProvider));
        }

        let mut news: Vec<std::sync::Arc<dyn NewsProvider>> = Vec::new();
        if let Some(key) = env_key("CURRENTS_API_KEY") {
            tracing::info!("OSINT: Currents news provider enabled");
            news.push(std::sync::Arc::new(currents::CurrentsNewsProvider::new(
                key,
            )));
        }
        if let Some(key) = env_key("NEWS_API_KEY") {
            tracing::info!("OSINT: NewsAPI news provider enabled");
            news.push(std::sync::Arc::new(news::RealNewsProvider::new(key)));
        }
        if news.is_empty() {
            news.push(std::sync::Arc::new(mock::MockNewsProvider));
        }

        let mut reverse_image: Vec<std::sync::Arc<dyn ReverseImageSearchProvider>> = Vec::new();
        if let Some(key) = env_key("TINEYE_API_KEY") {
            tracing::info!("OSINT: reverse-image source enabled");
            reverse_image.push(std::sync::Arc::new(
                tineye::TinEyeReverseImageProvider::new(key),
            ));
        }
        if let Some(key) = env_key("GOOGLE_CLOUD_VISION_API_KEY") {
            tracing::info!("OSINT: reverse-image source enabled");
            reverse_image.push(std::sync::Arc::new(
                google_vision::GoogleVisionWebDetectionProvider::new(key),
            ));
        }
        if let (Some(api_key), Some(folder_id)) = (
            env_key("YANDEX_SEARCH_API_KEY"),
            env_key("YANDEX_SEARCH_FOLDER_ID"),
        ) {
            tracing::info!("OSINT: reverse-image source enabled");
            reverse_image.push(std::sync::Arc::new(
                yandex_images::YandexImagesReverseProvider::new(api_key, folder_id),
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
        use futures::future::FutureExt;
        let web = self.web_search.iter().map(|provider| {
            async move { run_provider(provider.name(), provider.search(query).await) }.boxed()
        });
        let news = self.news.iter().map(|provider| {
            async move { run_provider(provider.name(), provider.search(query).await) }.boxed()
        });
        let social = self.social.iter().map(|provider| {
            async move { run_provider(provider.name(), provider.search(query).await) }.boxed()
        });
        futures::future::join_all(web.chain(news).chain(social)).await
    }

    pub async fn collect_web_and_news(
        &self,
        query: &str,
    ) -> (Vec<ProviderOutcome>, Vec<ProviderOutcome>) {
        let web = self.web_search.iter().map(|provider| async move {
            run_provider(provider.name(), provider.search(query).await)
        });
        let news = self.news.iter().map(|provider| async move {
            run_provider(provider.name(), provider.search(query).await)
        });
        futures::future::join(
            futures::future::join_all(web),
            futures::future::join_all(news),
        )
        .await
    }

    /// Search the public web directly with the sanitized probe image. Every
    /// configured reverse-image provider runs independently and concurrently;
    /// one provider's failure never suppresses another provider's result.
    pub async fn collect_reverse_image(&self, image_bytes: &[u8]) -> Vec<ProviderOutcome> {
        let outcomes = self.reverse_image.iter().map(|provider| async move {
            run_provider(provider.name(), provider.search_by_image(image_bytes).await)
        });
        futures::future::join_all(outcomes).await
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
        for provider in &self.reverse_image {
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

    static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clear_osint_env_keys() {
        for key in [
            "TAVILY_API_KEY",
            "BRAVE_SEARCH_API_KEY",
            "CURRENTS_API_KEY",
            "NEWS_API_KEY",
            "TINEYE_API_KEY",
            "GOOGLE_CLOUD_VISION_API_KEY",
            "YANDEX_SEARCH_API_KEY",
            "YANDEX_SEARCH_FOLDER_ID",
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
    async fn from_env_runs_all_configured_text_providers() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear_osint_env_keys();
        std::env::set_var("TAVILY_API_KEY", "test-key");
        std::env::set_var("BRAVE_SEARCH_API_KEY", "test-key");
        std::env::set_var("CURRENTS_API_KEY", "test-key");
        std::env::set_var("NEWS_API_KEY", "test-key");
        let orchestrator = EvidenceOrchestrator::from_env();
        assert_eq!(
            orchestrator.enabled_sources(),
            vec![
                "tavily-web-search",
                "brave-web-search",
                "currents-news",
                "newsapi",
                "mock-social",
            ]
        );
        clear_osint_env_keys();
    }

    #[tokio::test]
    async fn from_env_enables_all_configured_reverse_image_providers() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear_osint_env_keys();
        std::env::set_var("TINEYE_API_KEY", "test-key");
        std::env::set_var("GOOGLE_CLOUD_VISION_API_KEY", "test-key");
        std::env::set_var("YANDEX_SEARCH_API_KEY", "test-key");
        std::env::set_var("YANDEX_SEARCH_FOLDER_ID", "test-folder");
        let orchestrator = EvidenceOrchestrator::from_env();
        let reverse_names = orchestrator
            .provider_status()
            .into_iter()
            .filter(|status| status.slot == "reverse_image")
            .map(|status| status.provider_name)
            .collect::<Vec<_>>();
        assert_eq!(
            reverse_names,
            vec![
                "tineye-reverse-image",
                "google-vision-web-detection",
                "yandex-images-reverse-search",
            ]
        );
        clear_osint_env_keys();
    }
}
