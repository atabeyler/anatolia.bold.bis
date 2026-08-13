//! Reverse-image provider backed by the official TinEye API.
//! The sanitized probe image is uploaded directly to TinEye's `/search/`
//! endpoint; no public image URL is required. Results represent occurrences
//! of the same or modified image on the public web, not biometric identity
//! matches.

use async_trait::async_trait;
use reqwest::multipart::{Form, Part};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

use super::{EvidenceDetail, EvidenceItem, OsintError, ReverseImageSearchProvider};

const ENDPOINT: &str = "https://api.tineye.com/rest/search/";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESULTS: usize = 20;

pub struct TinEyeReverseImageProvider {
    client: reqwest::Client,
    api_key: String,
}

impl TinEyeReverseImageProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("failed to build TinEye HTTP client"),
            api_key,
        }
    }

    async fn search_bytes(&self, image_bytes: &[u8]) -> Result<Vec<EvidenceItem>, OsintError> {
        let part = Part::bytes(image_bytes.to_vec()).file_name("query.jpg");
        let form = Form::new()
            .part("image", part)
            .text("limit", MAX_RESULTS.to_string())
            .text("backlink_limit", MAX_RESULTS.to_string());

        let response = self
            .client
            .post(ENDPOINT)
            .header("x-api-key", &self.api_key)
            .multipart(form)
            .send()
            .await
            .map_err(|e| OsintError::ProviderUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(OsintError::ProviderUnavailable(format!(
                "TinEye API returned {}",
                response.status()
            )));
        }

        let body: TinEyeResponse = response
            .json()
            .await
            .map_err(|e| OsintError::Internal(format!("failed to parse TinEye response: {e}")))?;

        let mut items = Vec::new();
        for matched in body.results.matches.into_iter().take(MAX_RESULTS) {
            let ranking = (matched.score / 100.0).clamp(0.0, 1.0);
            for backlink in matched.backlinks.into_iter().take(MAX_RESULTS) {
                if items.len() >= MAX_RESULTS {
                    break;
                }
                let (title_key, title_params) = match matched
                    .domain
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
                {
                    Some(domain) => (
                        "osint.evidence.title.tineyeWithDomain",
                        Some(json!({ "domain": domain })),
                    ),
                    None => ("osint.evidence.title.tineyeGeneric", None),
                };
                let mut details = vec![EvidenceDetail {
                    key: "osint.evidence.detail.tineyeScore".to_string(),
                    params: json!({ "score": format!("{:.1}", matched.score) }),
                }];
                if let Some(image_url) = backlink.url.as_deref() {
                    details.push(EvidenceDetail {
                        key: "osint.evidence.detail.matchedImage".to_string(),
                        params: json!({ "url": image_url }),
                    });
                }
                if let Some(crawl_date) = backlink.crawl_date.as_deref() {
                    details.push(EvidenceDetail {
                        key: "osint.evidence.detail.crawled".to_string(),
                        params: json!({ "date": crawl_date }),
                    });
                }
                items.push(EvidenceItem {
                    source_type: "reverse_image".to_string(),
                    provider_name: "tineye-reverse-image".to_string(),
                    title: String::new(),
                    title_key: Some(title_key.to_string()),
                    title_params,
                    url: Some(backlink.backlink),
                    snippet: None,
                    details,
                    confidence: ranking,
                });
            }
        }

        Ok(items)
    }
}

#[async_trait]
impl ReverseImageSearchProvider for TinEyeReverseImageProvider {
    fn name(&self) -> &'static str {
        "tineye-reverse-image"
    }

    async fn search_by_image(&self, image_bytes: &[u8]) -> Result<Vec<EvidenceItem>, OsintError> {
        self.search_bytes(image_bytes).await
    }

    async fn search_by_image_url(&self, _image_url: &str) -> Result<Vec<EvidenceItem>, OsintError> {
        Err(OsintError::ProviderUnavailable(
            "this provider is configured for direct image-content requests".to_string(),
        ))
    }
}

#[derive(Debug, Deserialize, Default)]
struct TinEyeResponse {
    #[serde(default)]
    results: TinEyeResults,
}

#[derive(Debug, Deserialize, Default)]
struct TinEyeResults {
    #[serde(default)]
    matches: Vec<TinEyeMatch>,
}

#[derive(Debug, Deserialize)]
struct TinEyeMatch {
    #[serde(default)]
    score: f64,
    domain: Option<String>,
    #[serde(default)]
    backlinks: Vec<TinEyeBacklink>,
}

#[derive(Debug, Deserialize)]
struct TinEyeBacklink {
    backlink: String,
    url: Option<String>,
    crawl_date: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tineye_matches_and_backlinks() {
        let json = r#"{
          "results": {
            "matches": [{
              "score": 91.5,
              "domain": "example.test",
              "backlinks": [{
                "backlink": "https://example.test/page",
                "url": "https://example.test/photo.jpg",
                "crawl_date": "2026-01-01"
              }]
            }]
          }
        }"#;
        let parsed: TinEyeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.results.matches.len(), 1);
        assert_eq!(parsed.results.matches[0].backlinks.len(), 1);
        assert_eq!(parsed.results.matches[0].score, 91.5);
    }
}
