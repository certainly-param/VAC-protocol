use axum::{
    extract::Json,
    http::StatusCode,
    response::Json as ResponseJson,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Control Plane Mock Server for V-A-C Sidecar Testing
/// 
/// This mock server implements the heartbeat endpoint and provides:
/// - Heartbeat endpoint for sidecar health checks
/// - Revocation list management (token IDs)
/// - Kill switch endpoint to stop heartbeats
/// - Session key rotation triggers

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeartbeatRequest {
    sidecar_id: String,
    session_key_pub: String,
    timestamp: u64,
}

#[derive(Debug, Serialize)]
struct HeartbeatResponse {
    healthy: bool,
    #[serde(default)]
    revoked_token_ids: Option<Vec<[u8; 32]>>,
}

/// Sidecar state tracking
#[derive(Debug, Clone)]
struct SidecarInfo {
    sidecar_id: String,
    last_heartbeat: SystemTime,
    session_key_pub: String,
}

/// Control Plane state
struct ControlPlaneState {
    /// Registered sidecars
    sidecars: Arc<RwLock<HashMap<String, SidecarInfo>>>,
    /// Revoked token IDs (32-byte arrays)
    revoked_tokens: Arc<RwLock<Vec<[u8; 32]>>>,
    /// Kill switch: if true, all heartbeats return unhealthy
    kill_switch_active: Arc<RwLock<bool>>,
}

impl ControlPlaneState {
    fn new() -> Self {
        Self {
            sidecars: Arc::new(RwLock::new(HashMap::new())),
            revoked_tokens: Arc::new(RwLock::new(Vec::new())),
            kill_switch_active: Arc::new(RwLock::new(false)),
        }
    }
}

/// Heartbeat endpoint handler
/// 
/// POST /heartbeat
/// Receives heartbeat from sidecar and returns health status + revocation list
async fn handle_heartbeat(
    state: axum::extract::State<Arc<ControlPlaneState>>,
    Json(request): Json<HeartbeatRequest>,
) -> Result<ResponseJson<HeartbeatResponse>, StatusCode> {
    info!("💓 Heartbeat received from sidecar: {}", request.sidecar_id);
    
    // Check kill switch
    let kill_switch_active = *state.kill_switch_active.read()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if kill_switch_active {
        warn!("🚨 Kill switch active - returning unhealthy");
        return Ok(ResponseJson(HeartbeatResponse {
            healthy: false,
            revoked_token_ids: None,
        }));
    }
    
    // Update sidecar info
    {
        let mut sidecars = state.sidecars.write()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        sidecars.insert(
            request.sidecar_id.clone(),
            SidecarInfo {
                sidecar_id: request.sidecar_id.clone(),
                last_heartbeat: SystemTime::now(),
                session_key_pub: request.session_key_pub,
            },
        );
    }
    
    // Get revoked tokens
    let revoked_tokens = {
        let revoked = state.revoked_tokens.read()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if revoked.is_empty() {
            None
        } else {
            Some(revoked.clone())
        }
    };
    
    Ok(ResponseJson(HeartbeatResponse {
        healthy: true,
        revoked_token_ids: revoked_tokens,
    }))
}

/// Revoke a token
/// 
/// POST /revoke
/// Body: { "token_id": "hex-encoded-32-byte-token-id" }
#[derive(Debug, Deserialize)]
struct RevokeRequest {
    token_id: String, // Hex-encoded 32-byte token ID
}

async fn handle_revoke(
    state: axum::extract::State<Arc<ControlPlaneState>>,
    Json(request): Json<RevokeRequest>,
) -> Result<StatusCode, StatusCode> {
    // Parse hex-encoded token ID
    let token_id_bytes = hex::decode(&request.token_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    if token_id_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    let mut token_id = [0u8; 32];
    token_id.copy_from_slice(&token_id_bytes);
    
    // Add to revocation list
    {
        let mut revoked = state.revoked_tokens.write()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if !revoked.contains(&token_id) {
            revoked.push(token_id);
            info!("🚫 Token revoked: {}", request.token_id);
        }
    }
    
    Ok(StatusCode::OK)
}

/// Activate kill switch (stops all sidecars)
/// 
/// POST /kill
async fn handle_kill(
    state: axum::extract::State<Arc<ControlPlaneState>>,
) -> Result<StatusCode, StatusCode> {
    {
        let mut kill_switch = state.kill_switch_active.write()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        *kill_switch = true;
    }
    warn!("🚨 Kill switch activated - all sidecars will be marked unhealthy");
    Ok(StatusCode::OK)
}

/// Deactivate kill switch
/// 
/// POST /revive
async fn handle_revive(
    state: axum::extract::State<Arc<ControlPlaneState>>,
) -> Result<StatusCode, StatusCode> {
    {
        let mut kill_switch = state.kill_switch_active.write()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        *kill_switch = false;
    }
    info!("✅ Kill switch deactivated - sidecars will resume normal operation");
    Ok(StatusCode::OK)
}

/// List registered sidecars
/// 
/// GET /sidecars
async fn list_sidecars(
    state: axum::extract::State<Arc<ControlPlaneState>>,
) -> Result<ResponseJson<serde_json::Value>, StatusCode> {
    let sidecars = state.sidecars.read()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let sidecar_list: Vec<_> = sidecars
        .values()
        .map(|info| {
            serde_json::json!({
                "sidecar_id": info.sidecar_id,
                "session_key_pub": info.session_key_pub,
                "last_heartbeat": info.last_heartbeat
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            })
        })
        .collect();
    
    Ok(ResponseJson(serde_json::json!({
        "sidecars": sidecar_list,
        "count": sidecar_list.len(),
    })))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    let state = Arc::new(ControlPlaneState::new());
    
    let app = Router::new()
        .route("/heartbeat", post(handle_heartbeat))
        .route("/revoke", post(handle_revoke))
        .route("/kill", post(handle_kill))
        .route("/revive", post(handle_revive))
        .route("/sidecars", axum::routing::get(list_sidecars))
        .with_state(state);
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await?;
    info!("🎛️ V-A-C Control Plane Mock Server listening on 0.0.0.0:8081");
    info!("Endpoints:");
    info!("  POST /heartbeat - Receive heartbeat from sidecar");
    info!("  POST /revoke - Revoke a token ID");
    info!("  POST /kill - Activate kill switch");
    info!("  POST /revive - Deactivate kill switch");
    info!("  GET /sidecars - List registered sidecars");
    
    axum::serve(listener, app).await?;
    
    Ok(())
}
