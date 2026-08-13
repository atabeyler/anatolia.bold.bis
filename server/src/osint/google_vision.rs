//! Reverse-image/web-discovery provider backed by Google Cloud Vision's
//! official WEB_DETECTION feature. This is image matching, not biometric
//! identity matching. Low-signal visually-similar suggestions are deliberately
//! excluded because they are category/appearance neighbours, not evidence that
//! the uploaded photograph occurs at that URL.

use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::time::Duration;

use super::{EvidenceDetail, EvidenceItem, OsintError, ReverseImageSearchProvider};

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
        let body: VisionResponse = response.json().await.map_err(|e| {
            OsintError::Internal(format!("failed to parse Google Vision response: {e}"))
        })?;
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

        // A page is evidence only when Vision reports a full or partial match on
        // that page. Pages with no reported matching image are not promoted.
        for page in web.pages_with_matching_images {
            let exact_matches = page.full_matching_images.len();
            let partial_matches = page.partial_matching_images.len();
            if exact_matches == 0 && partial_matches == 0 {
                continue;
            }
            if !seen_urls.insert(page.url.clone()) {
                continue;
            }
            let (title, title_key) = page
                .page_title
                .filter(|v| !v.trim().is_empty())
                .map(|title| (title, None))
                .unwrap_or_else(|| {
                    (
                        String::new(),
                        Some("osint.evidence.title.webPageWithMatch".to_string()),
                    )
                });
            let mut details = Vec::new();
            if exact_matches > 0 {
                details.push(EvidenceDetail {
                    key: "osint.evidence.detail.fullMatches".to_string(),
                    params: json!({ "count": exact_matches }),
                });
            }
            if partial_matches > 0 {
                details.push(EvidenceDetail {
                    key: "osint.evidence.detail.partialMatches".to_string(),
                    params: json!({ "count": partial_matches }),
                });
            }
            if let Some(label) = best_guess.as_deref() {
                details.push(EvidenceDetail {
                    key: "osint.evidence.detail.bestGuess".to_string(),
                    params: json!({ "label": label }),
                });
            }
            items.push(EvidenceItem {
                source_type: "reverse_image".to_string(),
                provider_name: "google-vision-web-detection".to_string(),
                title,
                title_key,
                title_params: None,
                url: Some(page.url),
                snippet: None,
                details,
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
                title: String::new(),
                title_key: Some("osint.evidence.title.fullMatchingImage".to_string()),
                title_params: None,
                url: Some(image.url),
                snippet: None,
                details: best_guess
                    .as_deref()
                    .map(|label| {
                        vec![EvidenceDetail {
                            key: "osint.evidence.detail.bestGuess".to_string(),
                            params: json!({ "label": label }),
                        }]
                    })
                    .unwrap_or_default(),
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
                title: String::new(),
                title_key: Some("osint.evidence.title.partialMatchingImage".to_string()),
                title_params: None,
                url: Some(image.url),
                snippet: None,
                details: best_guess
                    .as_deref()
                    .map(|label| {
                        vec![EvidenceDetail {
                            key: "osint.evidence.detail.bestGuess".to_string(),
                            params: json!({ "label": label }),
                        }]
                    })
                    .unwrap_or_default(),
                confidence: 0.75,
            });
        }

        // Do not return `visuallySimilarImages`: Vision uses these for broad
        // visual/category similarity (for example a generic "gentleman" label).
        // Treating them as reverse-image hits creates misleading OSINT evidence.
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
    #[serde(default, rename = "visuallySimilarImages")]
    _visually_similar_images: Vec<WebImage>,
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
        let body = r#"{"responses":[{"webDetection":{"pagesWithMatchingImages":[{"url":"https://example.test/person","pageTitle":"Example profile","fullMatchingImages":[{"url":"https://example.test/photo.jpg"}]}],"fullMatchingImages":[{"url":"https://example.test/photo.jpg"}],"bestGuessLabels":[{"label":"example person"}]}}]}"#;
        let parsed: VisionResponse = serde_json::from_str(body).unwrap();
        let web = parsed.responses[0].web_detection.as_ref().unwrap();
        assert_eq!(web.pages_with_matching_images.len(), 1);
        assert_eq!(web.full_matching_images.len(), 1);
        assert_eq!(web.best_guess_labels[0].label, "example person");
    }
}
