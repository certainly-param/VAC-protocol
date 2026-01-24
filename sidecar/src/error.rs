use axum::{http::StatusCode, response::IntoResponse};
use thiserror::Error;

/// V-A-C Sidecar error types with explicit fail-closed enforcement
#[derive(Debug, Error)]
pub enum VacError {
    #[error("Missing authorization token")]
    MissingToken,
    
    #[error("Invalid token format")]
    InvalidTokenFormat,
    
    #[error("Invalid biscuit signature")]
    InvalidSignature,
    
    #[error("Receipt expired")]
    ReceiptExpired,
    
    #[error("Correlation ID mismatch")]
    CorrelationIdMismatch,
    
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
    
    #[error("Request denied by fail-closed policy")]
    Deny,
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Internal server error: {0}")]
    InternalError(String),
    
    #[error("Proxy error: {0}")]
    ProxyError(String),
    
    #[error("Receipt verification failed: {0}")]
    ReceiptError(String),
}

impl From<VacError> for StatusCode {
    fn from(err: VacError) -> Self {
        From::from(&err)
    }
}

impl IntoResponse for VacError {
    fn into_response(self) -> axum::response::Response {
        let status: StatusCode = From::from(&self);
        let body = format!("{}", self);
        (status, body).into_response()
    }
}

impl From<&VacError> for StatusCode {
    fn from(err: &VacError) -> Self {
        match err {
            VacError::MissingToken => StatusCode::UNAUTHORIZED,
            VacError::InvalidTokenFormat => StatusCode::BAD_REQUEST,
            VacError::InvalidSignature => StatusCode::FORBIDDEN,
            VacError::ReceiptExpired => StatusCode::FORBIDDEN,
            VacError::CorrelationIdMismatch => StatusCode::CONFLICT,
            VacError::PolicyViolation(_) => StatusCode::FORBIDDEN,
            VacError::Deny => StatusCode::FORBIDDEN,
            VacError::ConfigError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            VacError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            VacError::ProxyError(_) => StatusCode::BAD_GATEWAY,
            VacError::ReceiptError(_) => StatusCode::FORBIDDEN,
        }
    }
}

// Note: biscuit-auth errors are handled inline in biscuit.rs and receipt.rs
// We don't provide a generic conversion here since error types vary

impl From<hex::FromHexError> for VacError {
    fn from(_: hex::FromHexError) -> Self {
        VacError::ConfigError("Invalid hex encoding for public key".to_string())
    }
}

impl From<reqwest::Error> for VacError {
    fn from(err: reqwest::Error) -> Self {
        VacError::ProxyError(format!("HTTP request failed: {}", err))
    }
}
