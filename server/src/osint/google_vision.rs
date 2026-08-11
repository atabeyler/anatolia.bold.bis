//! Reverse-image/web-discovery provider backed by Google Cloud Vision's
//! official WEB_DETECTION feature. Unlike the text-only Tavily/Brave and
//! Currents/NewsAPI providers, this provider receives the sanitized probe
//! image itself and asks Google for pages/images on the public web that
//! visually match it. It is opt-in through `GOOGLE_CLOUD_VISION_API_KEY`;
//! when that variable is absent no image leaves the application through
//! this capability.

use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

use super::{EvidenceItem, OsintError, ReverseImageSearchProvider};

const ENDPOINT: &str = "https://vision.googleapis.com/v1/images:annotate";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_RESULTS: u32 = 20;

pub struct GoogleVisionWebDetectionProvider {
    client: reqwest::Client,
    api_key: String,
}

impl GoogleVisionWebDetectionProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("failed to build Google Vision HTTP client"),
            api_key,
        }
    }

    async fn annotate(&self, image_bytes: &[u8]) -> Result<Vec<EvidenceItem>, OsintError> {
        let content = base64::engine::general_purpose::STANDARD.encode(image_bytes);
        let request = VisionRequest {
            requests: vec![AnnotateRequest {
                image: ImageContent { content },
                features: vec![Feature {
                    feature_type: "WEB_DETECTION",
                    max_results: MAX_RESULTS,
                }],
            }],
        };

        let response = self
            .client
            .post(ENDPOINT)
            .query(&[("key", self.api_key.as_str())])
            .json(&request)
            .send()
            .await
            .map_err(|e| OsintError::ProviderUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(OsintError::ProviderUnavailable(format!(
                "Google Vision API returned {}",
                response.status()
            )));
        }

        let body: VisionResponse = response
            .json()
            .await
            .map_err(|e| OsintError::Internal(format!("failed to parse Google Vision response: {e}")))?;

        let Some(first) = body.responses.into_iter().next() else {
            return Ok(Vec::new());
        };
        if let Some(error) = first.error {
            return Err(OsintError::ProviderUnavailable(error.message));
        }
        let Some(web) = first.web_detection else {
            return Ok(Vec::new());
        };

        let best_guess = web
            .best_guess_labels
            .first()
            .map(|label| label.label.clone());
        let mut seen_urls = HashSet::new();
        let mut items = Vec::new();

        for page in web.pages_with_matching_images {
            if !seen_urls.insert(page.url.clone()) {
                continue;
            }
            let exact_matches = page.full_matching_images.len();
            let partial_matches = page.partial_matching_images.len();
            let title = page
                .page_title
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "Web page containing a matching image".to_string());
            let mut details = Vec::new();
            if exact_matches > 0 {
                details.push(format!("{exact_matches} full image match(es)"));
            }
            if partial_matches > 0 {
                details.push(format!("{partial_matches} partial image match(es)"));
            }
            if let Some(label) = best_guess.as_deref() {
                details.push(format!("best guess: {label}"));
            }
            items.push(EvidenceItem {
                source_type: "reverse_image".to_string(),
                provider_name: "google-vision-web-detection".to_string(),
                title,
                url: Some(page.url),
                snippet: (!details.is_empty()).then(|| details.join(" · ")),
                confidence: if exact_matches > 0 { 0.95 } else { 0.75 },
            });
        }

        for image in web.full_matching_images {
            if !seen_urls.insert(image.url.clone()) {
                continue;
            }
            items.push(EvidenceItem {
                source_type: "reverse_image".to_string(),
                provider_name: "google-vision-web-detection".to_string(),
                title: "Full matching image".to_string(),
                url: Some(image.url),
                snippet: best_guess.clone(),
                confidence: 0.95,
            });
        }

        for image in web.partial_matching_images {
            if !seen_urls.insert(image.url.clone()) {
                continue;
            }
            items.push(EvidenceItem {
                source_type: "reverse_image".to_string(),
                provider_name: "google-vision-web-detection".to_string(),
                title: "Partial matching image".to_string(),
                url: Some(image.url),
                snippet: best_guess.clone(),
                confidence: 0.75,
            });
        }

        for image in web.visually_similar_images {
            if !seen_urls.insert(image.url.clone()) {
                continue;
            }
            items.push(EvidenceItem {
                source_type: "reverse_image".to_string(),
                provider_name: "google-vision-web-detection".to_string(),
                title: "Visually similar image".to_string(),
                url: Some(image.url),
                snippet: best_guess.clone(),
                confidence: 0.55,
            });
        }

        items.truncate(MAX_RESULTS as usize);
        Ok(items)
    }
}

#[async_trait]
impl ReverseImageSearchProvider for GoogleVisionWebDetectionProvider {
    fn name(&self) -> &'static str {
        "google-vision-web-detection"
    }

    async fn search_by_image(&self, image_bytes: &[u8]) -> Result<Vec<EvidenceItem>, OsintError> {
        self.annotate(image_bytes).await
    }

    async fn search_by_image_url(&self, _image_url: &str) -> Result<Vec<EvidenceItem>, OsintError> {
        Err(OsintError::ProviderUnavailable(
            "this provider is configured for direct image-content requests".to_string(),
        ))
    }
}

#[derive(Serialize)]
struct VisionRequest {
    requests: Vec<AnnotateRequest>,
}

#[derive(Serialize)]
struct AnnotateRequest {
    image: ImageContent,
    features: Vec<Feature>,
}

#[derive(Serialize)]
struct ImageContent {
    content: String,
}

#[derive(Serialize)]
struct Feature {
    #[serde(rename = "type")]
    feature_type: &'static str,
    #[serde(rename = "maxResults")]
    max_results: u32,
}

#[derive(Deserialize)]
struct VisionResponse {
    #[serde(default)]
    responses: Vec<AnnotateResponse>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AnnotateResponse {
    web_detection: Option<WebDetection>,
    error: Option<VisionError>,
}

#[derive(Deserialize)]
struct VisionError {
    message: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct WebDetection {
    #[serde(default)]
    full_matching_images: Vec<WebImage>,
    #[serde(default)]
    partial_matching_images: Vec<WebImage>,
    #[serde(default)]
    pages_with_matching_images: Vec<WebPage>,
    #[serde(default)]
    visually_similar_images: Vec<WebImage>,
    #[serde(default)]
    best_guess_labels: Vec<BestGuessLabel>,
}

#[derive(Deserialize)]
struct WebImage {
    url: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebPage {
    url: String,
    page_title: Option<String>,
    #[serde(default)]
    full_matching_images: Vec<WebImage>,
    #[serde(default)]
    partial_matching_images: Vec<WebImage>,
}

#[derive(Deserialize)]
struct BestGuessLabel {
    label: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_web_detection_response() {
        let body = r#"{
          "responses": [{
            "webDetection": {
              "pagesWithMatchingImages": [{
                "url": "https://example.test/person",
                "pageTitle": "Example profile",
                "fullMatchingImages": [{"url": "https://example.test/photo.jpg"}]
              }],
              "fullMatchingImages": [{"url": "https://example.test/photo.jpg"}],
              "bestGuessLabels": [{"label": "example person"}]
            }
          }]
        }"#;
        let parsed: VisionResponse = serde_json::from_str(body).unwrap();
        let web = parsed.responses[0].web_detection.as_ref().unwrap();
        assert_eq!(web.pages_with_matching_images.len(), 1);
        assert_eq!(web.full_matching_images.len(), 1);
        assert_eq!(web.best_guess_labels[0].label, "example person");
    }
}
