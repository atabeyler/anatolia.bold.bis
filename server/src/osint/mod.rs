//! OSINT/evidence provider abstraction (P2 "Connector / OSINT Katmanı"
//! appendix in `docs/HARDENING_CHECKLIST.md` — planned as its own
//! milestone, unstarted before this). This module implements a first,
//! deliberately scoped slice of it: provider abstractions
//! (`WebSearchProvider`/`NewsProvider`/`AuthorizedSocialProvider`), a
//! `SourceRegistry` of which named sources are actually enabled, a mock
//! implementation of each (no real external API calls — this environment
//! has no authorized OSINT API access), and an orchestrator that isolates
//! one provider's failure from the others. Entity resolution over the
//! collected evidence, an entity graph, reverse image search, and an
//! OSINT-specific frontend UI are explicitly out of scope here — each is
//! its own, larger piece of work.
//!
//! Mirrors the `biometric` module's shape: a trait per capability, a
//! `Mock*` implementation for every trait, and a real implementation
//! (when one exists) behind the same interface so callers never branch on
//! which is active.

pub mod mock;
pub mod news;
pub mod resilience;
pub mod websearch;

use async_trait::async_trait;

/// Shorthand used throughout the real-provider implementations.
pub type EvidenceItems = Vec<EvidenceItem>;

/// One piece of evidence returned by a provider, before it's persisted as
/// a `candidate_evidence` row (see `db::evidence`).
#[derive(Debug, Clone)]
pub struct EvidenceItem {
    pub source_type: String,
    pub provider_name: String,
    pub title: String,
    pub url: Option<String>,
    pub snippet: Option<String>,
    /// The provider's own confidence in this item's relevance, `[0, 1]`.
    /// Never a match/no-match verdict — same "candidates, not verdicts"
    /// principle CLAUDE.md applies to biometric scores applies here: a
    /// human reviewer decides what evidence means.
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

/// Deliberately named `Authorized*`: unlike `WebSearchProvider`/
/// `NewsProvider`, a real implementation of this trait must only ever
/// query a source the deployment has an explicit, declared authorization
/// to query (e.g. a platform API with a signed agreement) — never scrape
/// a social platform without one. `docs/SECURITY_ARCHITECTURE.md`
/// documents this constraint; enforcing it is a real-provider concern,
/// since the mock implementation makes no real request at all.
#[async_trait]
pub trait AuthorizedSocialProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn search(&self, query: &str) -> Result<Vec<EvidenceItem>, OsintError>;
}

/// Which named sources are currently enabled for evidence collection.
/// Exists as its own trait (rather than just checking `is_empty()` on the
/// orchestrator's provider lists) so a future real implementation can
/// report richer per-source metadata (rate limits, authorization type —
/// see the OSINT appendix) without changing the orchestrator's shape.
pub trait SourceRegistry: Send + Sync {
    fn enabled_sources(&self) -> Vec<&'static str>;
}

/// One provider's outcome from a single `collect` run — success with its
/// items, or a failure that must not prevent the other providers' results
/// from being returned (provider failure isolation).
pub struct ProviderOutcome {
    pub provider_name: String,
    pub items: Vec<EvidenceItem>,
    pub error: Option<String>,
}

/// Runs every configured provider and collects each one's outcome
/// independently — one provider failing (timeout, misconfiguration,
/// upstream error) never prevents the others from contributing evidence,
/// and never fails the whole collection request.
pub struct EvidenceOrchestrator {
    web_search: Vec<std::sync::Arc<dyn WebSearchProvider>>,
    news: Vec<std::sync::Arc<dyn NewsProvider>>,
    social: Vec<std::sync::Arc<dyn AuthorizedSocialProvider>>,
}

impl EvidenceOrchestrator {
    pub fn new(
        web_search: Vec<std::sync::Arc<dyn WebSearchProvider>>,
        news: Vec<std::sync::Arc<dyn NewsProvider>>,
        social: Vec<std::sync::Arc<dyn AuthorizedSocialProvider>>,
    ) -> Self {
        Self {
            web_search,
            news,
            social,
        }
    }

    pub fn mock() -> Self {
        Self::new(
            vec![std::sync::Arc::new(mock::MockWebSearchProvider)],
            vec![std::sync::Arc::new(mock::MockNewsProvider)],
            vec![std::sync::Arc::new(mock::MockSocialProvider)],
        )
    }

    /// Builds the real orchestrator this deployment should actually run:
    /// each provider slot uses its real implementation when the matching
    /// API key is configured (`BRAVE_SEARCH_API_KEY` for web search,
    /// `NEWS_API_KEY` for news), and falls back to that slot's mock
    /// implementation otherwise — so an operator can enable providers
    /// incrementally, and a deployment with no keys configured at all
    /// behaves exactly like `mock()`. There is no real
    /// `AuthorizedSocialProvider` implementation yet (see the trait's doc
    /// comment on why a real one is more than an API-key away); that slot
    /// is always the mock today.
    pub fn from_env() -> Self {
        let web_search: Vec<std::sync::Arc<dyn WebSearchProvider>> =
            match std::env::var("BRAVE_SEARCH_API_KEY") {
                Ok(key) if !key.trim().is_empty() => {
                    tracing::info!("OSINT: Brave Search web-search provider enabled");
                    vec![std::sync::Arc::new(websearch::RealWebSearchProvider::new(
                        key,
                    ))]
                }
                _ => vec![std::sync::Arc::new(mock::MockWebSearchProvider)],
            };
        let news: Vec<std::sync::Arc<dyn NewsProvider>> = match std::env::var("NEWS_API_KEY") {
            Ok(key) if !key.trim().is_empty() => {
                tracing::info!("OSINT: NewsAPI news provider enabled");
                vec![std::sync::Arc::new(news::RealNewsProvider::new(key))]
            }
            _ => vec![std::sync::Arc::new(mock::MockNewsProvider)],
        };
        Self::new(
            web_search,
            news,
            vec![std::sync::Arc::new(mock::MockSocialProvider)],
        )
    }

    /// Runs every provider for `query`, isolating failures per provider.
    /// The returned `Vec` always has one entry per configured provider,
    /// in a stable order (web search, then news, then social).
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
        );
        let outcomes = orchestrator.collect("test query").await;
        assert_eq!(outcomes.len(), 4);
        assert_eq!(outcomes[0].provider_name, "failing-web-search");
        assert!(outcomes[0].error.is_some());
        assert!(outcomes[0].items.is_empty());
        // The other providers still ran and produced items.
        assert!(outcomes[1].error.is_none());
        assert!(!outcomes[1].items.is_empty());
        assert!(outcomes[2].error.is_none());
        assert!(outcomes[3].error.is_none());
    }

    #[tokio::test]
    async fn mock_orchestrator_reports_every_configured_source() {
        let orchestrator = EvidenceOrchestrator::mock();
        let sources = orchestrator.enabled_sources();
        assert_eq!(sources.len(), 3);
    }

    #[tokio::test]
    async fn mock_providers_are_deterministic_for_the_same_query() {
        let orchestrator = EvidenceOrchestrator::mock();
        let first = orchestrator.collect("Jane Doe").await;
        let second = orchestrator.collect("Jane Doe").await;
        assert_eq!(first[0].items.len(), second[0].items.len());
        assert_eq!(first[0].items[0].title, second[0].items[0].title);
    }

    // Serialized: both mutate the same process-wide env vars.
    static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn from_env_falls_back_to_every_mock_provider_when_no_keys_are_set() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("BRAVE_SEARCH_API_KEY");
        std::env::remove_var("NEWS_API_KEY");
        let orchestrator = EvidenceOrchestrator::from_env();
        let sources = orchestrator.enabled_sources();
        assert_eq!(sources, vec!["mock-web-search", "mock-news", "mock-social"]);
    }

    #[tokio::test]
    async fn from_env_uses_the_real_provider_once_its_api_key_is_set() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("BRAVE_SEARCH_API_KEY", "test-key");
        std::env::set_var("NEWS_API_KEY", "test-key");
        let orchestrator = EvidenceOrchestrator::from_env();
        let sources = orchestrator.enabled_sources();
        assert_eq!(sources, vec!["brave-web-search", "newsapi", "mock-social"]);
        std::env::remove_var("BRAVE_SEARCH_API_KEY");
        std::env::remove_var("NEWS_API_KEY");
    }
}
