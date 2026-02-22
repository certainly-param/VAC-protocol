use axum::{
    body::{Body, Bytes},
    http::{Response, StatusCode, HeaderValue, Method, Uri},
};
use crate::error::VacError;
use reqwest::Client;
use std::str::FromStr;

/// HTTP proxy trait for future framework abstraction
/// 
/// This allows swapping Axum → Pingora in Phase 4 if needed.
/// Accepts pre-read request parts and body bytes to avoid double body reads.
#[allow(async_fn_in_trait)] // Known limitation: async fn in traits, but needed for trait abstraction
pub trait Proxy: Send + Sync {
    async fn forward(
        &self,
        parts: &axum::http::request::Parts,
        body_bytes: Bytes,
        api_key: &str,
        upstream_url: &str,
    ) -> Result<Response<Body>, VacError>;
}

/// Axum-based HTTP proxy implementation
pub struct AxumProxy {
    client: Client,
}

impl AxumProxy {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

impl Proxy for AxumProxy {
    async fn forward(
        &self,
        parts: &axum::http::request::Parts,
        body_bytes: Bytes,
        api_key: &str,
        upstream_url: &str,
    ) -> Result<Response<Body>, VacError> {
        // Build upstream URL
        let path = parts.uri.path();
        let query = parts.uri.query().unwrap_or("");
        let upstream_uri = if query.is_empty() {
            format!("{}{}", upstream_url, path)
        } else {
            format!("{}{}?{}", upstream_url, path, query)
        };
        
        let uri = Uri::from_str(&upstream_uri)
            .map_err(|e| VacError::ProxyError(format!("Invalid upstream URL: {}", e)))?;
        
        // Build reqwest request — body bytes are already read and validated
        let reqwest_method = match parts.method {
            Method::GET => reqwest::Method::GET,
            Method::POST => reqwest::Method::POST,
            Method::PUT => reqwest::Method::PUT,
            Method::DELETE => reqwest::Method::DELETE,
            Method::PATCH => reqwest::Method::PATCH,
            _ => {
                return Err(VacError::ProxyError(format!("Unsupported HTTP method: {}", parts.method)));
            }
        };
        
        let mut reqwest_req = self.client
            .request(reqwest_method, uri.to_string())
            .body(body_bytes);
        
        // Copy headers (except sensitive ones we'll inject)
        for (name, value) in &parts.headers {
            // Skip headers that should be stripped or replaced
            if name.as_str() == "authorization" {
                continue; // Will be replaced with API key
            }
            if name.as_str() == "host" {
                continue; // Will be set by reqwest
            }
            if name.as_str().starts_with("x-vac-") {
                continue; // Strip V-A-C internal headers
            }
            
            // Convert HeaderValue to str for reqwest
            if let Ok(value_str) = value.to_str() {
                reqwest_req = reqwest_req.header(name.as_str(), value_str);
            }
        }
        
        // CRITICAL: Inject real API key only after policy verification
        reqwest_req = reqwest_req.header("Authorization", format!("Bearer {}", api_key));
        
        // Execute request
        let response = reqwest_req
            .send()
            .await
            .map_err(|e| VacError::ProxyError(format!("Upstream request failed: {}", e)))?;
        
        // Convert reqwest::Response to axum::Response
        let status = StatusCode::from_u16(response.status().as_u16())
            .map_err(|_| VacError::ProxyError("Invalid status code from upstream".to_string()))?;
        
        let mut axum_response = Response::builder()
            .status(status);
        
        // Copy response headers
        for (name, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                axum_response = axum_response.header(
                    name.as_str(),
                    HeaderValue::from_str(value_str)
                        .map_err(|e| VacError::ProxyError(format!("Invalid header value: {}", e)))?,
                );
            }
        }
        
        // Convert response body
        let body_bytes = response.bytes().await
            .map_err(|e| VacError::ProxyError(format!("Failed to read response body: {}", e)))?;
        
        let body = Body::from(body_bytes);
        
        axum_response
            .body(body)
            .map_err(|e| VacError::ProxyError(format!("Failed to build response: {}", e)))
    }
}

impl Default for AxumProxy {
    fn default() -> Self {
        Self::new()
    }
}
