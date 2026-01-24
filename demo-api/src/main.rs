// Simple demo API server for testing V-A-C sidecar
// This simulates an upstream API service that the sidecar forwards requests to

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Clone)]
struct AppState {
    api_key: String,
    port: u16,
}

#[derive(Serialize, Deserialize)]
struct ApiResponse {
    success: bool,
    message: String,
    data: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
struct ChargeRequest {
    amount: u64,
    currency: String,
    description: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ChargeResponse {
    id: String,
    amount: u64,
    currency: String,
    status: String,
}

#[derive(Serialize, Deserialize)]
struct SearchRequest {
    query: String,
}

#[derive(Serialize, Deserialize)]
struct SearchResponse {
    results: Vec<serde_json::Value>,
    count: usize,
}

/// Extract and verify API key from Authorization header
fn verify_api_key(headers: &HeaderMap, expected_key: &str) -> Result<(), StatusCode> {
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if token != expected_key {
        warn!("Invalid API key provided");
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(())
}

/// Health check endpoint
async fn health() -> Json<ApiResponse> {
    Json(ApiResponse {
        success: true,
        message: "Demo API is healthy".to_string(),
        data: None,
    })
}

/// Search endpoint (simulates a search operation)
async fn search(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<SearchRequest>,
) -> Result<Json<ApiResponse>, StatusCode> {
    verify_api_key(&headers, &state.api_key)?;

    info!("Search request: query='{}'", payload.query);

    let results = vec![
        json!({"id": "1", "title": format!("Result for: {}", payload.query), "score": 0.95}),
        json!({"id": "2", "title": format!("Another result for: {}", payload.query), "score": 0.87}),
    ];

    Ok(Json(ApiResponse {
        success: true,
        message: format!("Found {} results", results.len()),
        data: Some(json!({
            "results": results,
            "count": results.len(),
            "query": payload.query
        })),
    }))
}

/// Charge endpoint (simulates a payment charge)
async fn charge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ChargeRequest>,
) -> Result<Json<ApiResponse>, StatusCode> {
    verify_api_key(&headers, &state.api_key)?;

    info!("Charge request: amount={} {}", payload.amount, payload.currency);

    // Simulate charge processing
    let charge_id = format!("ch_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));

    Ok(Json(ApiResponse {
        success: true,
        message: "Charge processed successfully".to_string(),
        data: Some(json!({
            "id": charge_id,
            "amount": payload.amount,
            "currency": payload.currency,
            "status": "succeeded",
            "description": payload.description
        })),
    }))
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Parse CLI arguments
    let args = Args::parse();
    
    // Check environment variables if CLI args not provided
    let api_key = args.api_key
        .or_else(|| std::env::var("DEMO_API_KEY").ok())
        .unwrap_or_else(|| "demo-api-key".to_string());
    
    let port = args.port
        .or_else(|| std::env::var("DEMO_API_PORT").ok().and_then(|v| v.parse().ok()))
        .unwrap_or(8080u16);

    let state = Arc::new(AppState { api_key, port });

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/search", post(search))
        .route("/charge", post(charge))
        .with_state(state.clone());

    let addr = format!("0.0.0.0:{}", state.port);
    info!("🚀 V-A-C Demo API starting on {}", addr);
    info!("📝 API Key: {}", state.api_key);
    info!("📚 Endpoints:");
    info!("   GET  /health - Health check (no auth)");
    info!("   POST /search - Search endpoint (requires API key)");
    info!("   POST /charge - Charge endpoint (requires API key)");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(Parser)]
#[command(name = "vac-demo-api")]
#[command(about = "Demo API server for testing V-A-C sidecar")]
struct Args {
    /// API key required for authentication
    #[arg(long)]
    api_key: Option<String>,

    /// Port to listen on
    #[arg(long)]
    port: Option<u16>,
}
