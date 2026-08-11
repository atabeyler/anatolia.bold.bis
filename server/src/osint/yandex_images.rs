//! Reverse-image provider backed by the official Yandex Search API.
//! The sanitized probe image is sent as Base64 data to Yandex image search.
//! Results are public-web image occurrences and visually related image pages;
//! they are evidence items, never biometric identity verdicts.

use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

use super::{EvidenceItem, OsintError, ReverseImageSearchProvider};

const ENDPOINT: &str = "https://searchapi.api.cloud.yandex.net/v2/image/search_by_image";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESULTS: usize = 20;

pub struct YandexImagesReverseProvider {
    client: reqwest::Client,
    api_key: String,
    folder_id: String,
}

impl YandexImagesReverseProvider {
    pub fn new(api_key: String, folder_id: String) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("failed to build Yandex image-search HTTP client"),
            api_key,
            folder_id,
        }
    }

    async fn search_bytes(&self, image_bytes: &[u8]) -> Result<Vec<EvidenceItem>, OsintError> {
        let request = SearchByImageRequest {
            folder_id: self.folder_id.clone(),
            data: base64::engine::general_purpose::STANDARD.encode(image_bytes),
            page: "0".to_string(),
            family_mode: "FAMILY_MODE_MODERATE",
        };

        let response = self
            .client
            .post(ENDPOINT)
            .header("Authorization", format!("Api-Key {}", self.api_key))
            .json(&request)
            .send()
            .await
            .map_err(|e| OsintError::ProviderUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(OsintError::ProviderUnavailable(format!(
                "Yandex Search API returned {}",
                response.status()
            )));
        }

        let body: SearchByImageResponse = response.json().await.map_err(|e| {
            OsintError::Internal(format!("failed to parse Yandex image-search response: {e}"))
        })?;

        let mut seen = HashSet::new();
        let mut items = Vec::new();
        for image in body.images.into_iter().take(MAX_RESULTS) {
            let target_url = image.page_url.clone().unwrap_or_else(|| image.url.clone());
            if !seen.insert(target_url.clone()) {
                continue;
            }
            let title = image
                .page_title
                .filter(|v| !v.trim().is_empty())
                .or_else(|| image.host.filter(|v| !v.trim().is_empty()))
                .unwrap_or_else(|| "Public page containing a related image".to_string());
            let mut details = Vec::new();
            if !image.url.trim().is_empty() {
                details.push(format!("image: {}", image.url));
            }
            if let (Some(width), Some(height)) = (image.width.as_deref(), image.height.as_deref()) {
                details.push(format!("dimensions: {width}×{height}"));
            }
            if let Some(passage) = image.passage.filter(|v| !v.trim().is_empty()) {
                details.push(passage);
            }
            items.push(EvidenceItem {
                source_type: "reverse_image".to_string(),
                provider_name: "yandex-images-reverse-search".to_string(),
                title,
                url: Some(target_url),
                snippet: (!details.is_empty()).then(|| details.join(" · ")),
                confidence: 0.7,
            });
        }
        Ok(items)
    }
}

#[async_trait]
impl ReverseImageSearchProvider for YandexImagesReverseProvider {
    fn name(&self) -> &'static str {
        "yandex-images-reverse-search"
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchByImageRequest {
    folder_id: String,
    data: String,
    page: String,
    family_mode: &'static str,
}

#[derive(Debug, Deserialize, Default)]
struct SearchByImageResponse {
    #[serde(default)]
    images: Vec<YandexImageInfo>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct YandexImageInfo {
    url: String,
    host: Option<String>,
    page_title: Option<String>,
    page_url: Option<String>,
    passage: Option<String>,
    width: Option<String>,
    height: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yandex_image_search_response() {
        let json = r#"{
          "images": [{
            "url": "https://img.example/photo.jpg",
            "host": "example.test",
            "pageTitle": "Example profile",
            "pageUrl": "https://example.test/profile",
            "passage": "Example passage",
            "width": "640",
            "height": "480"
          }],
          "page": "0",
          "maxPage": "1",
          "id": "cbir-id"
        }"#;
        let parsed: SearchByImageResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.images.len(), 1);
        assert_eq!(
            parsed.images[0].page_url.as_deref(),
            Some("https://example.test/profile")
        );
    }
}
