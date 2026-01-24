use crate::error::VacError;
use crate::state::SharedState;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use tracing::{error, info, warn};
use base64::{Engine as _, engine::general_purpose};

/// Maximum heartbeat failures before entering lockdown mode
const MAX_HEARTBEAT_FAILURES: u32 = 3;

/// Heartbeat request payload
#[derive(Debug, Serialize)]
struct HeartbeatRequest {
    sidecar_id: String,
    session_key_pub: String, // Base64-encoded public key
    timestamp: u64,
}

/// Heartbeat response payload
#[derive(Debug, Deserialize)]
struct HeartbeatResponse {
    healthy: bool,
    #[serde(default)]
    revoked_token_ids: Option<Vec<[u8; 32]>>, // List of revoked token IDs (32-byte arrays)
}

/// Start the heartbeat task
/// 
/// This runs in the background and pings the Control Plane every `interval_secs` seconds.
/// On failure, it increments the failure count. After MAX_HEARTBEAT_FAILURES failures,
/// it enters lockdown mode.
pub async fn start_heartbeat_task(
    state: SharedState,
    control_plane_url: String,
    interval_secs: u64,
    rotation_interval_secs: u64,
) {
    let interval = Duration::from_secs(interval_secs);
    let mut interval_timer = tokio::time::interval(interval);
    interval_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    
    info!("💓 Heartbeat task started (interval: {}s, control plane: {})", interval_secs, control_plane_url);
    
    loop {
        interval_timer.tick().await;
        
        match send_heartbeat(&state, &control_plane_url, rotation_interval_secs).await {
            Ok(should_continue) => {
                if !should_continue {
                    warn!("💓 Control Plane requested shutdown");
                    break;
                }
                
                // Update heartbeat state
                {
                    let mut s = state.write().map_err(|_| {
                        VacError::InternalError("Failed to acquire state lock".to_string())
                    }).unwrap();
                    s.heartbeat_healthy = true;
                    s.heartbeat_failure_count = 0;
                    s.last_heartbeat = SystemTime::now();
                }
            }
            Err(e) => {
                error!("💓 Heartbeat failed: {}", e);
                
                // Increment failure count
                let failure_count = {
                    let mut s = state.write().map_err(|_| {
                        VacError::InternalError("Failed to acquire state lock".to_string())
                    }).unwrap();
                    s.heartbeat_healthy = false;
                    s.heartbeat_failure_count += 1;
                    let count = s.heartbeat_failure_count;
                    
                    // Enter lockdown after MAX failures
                    if count >= MAX_HEARTBEAT_FAILURES {
                        warn!("🚨 Entering lockdown mode after {} heartbeat failures", count);
                        s.enter_lockdown();
                    }
                    
                    count
                };
                
                if failure_count >= MAX_HEARTBEAT_FAILURES {
                    error!("🚨 Lockdown mode activated - all non-read-only requests will be rejected");
                }
            }
        }
    }
}

/// Send a heartbeat to the Control Plane
async fn send_heartbeat(
    state: &SharedState,
    control_plane_url: &str,
    rotation_interval_secs: u64,
) -> Result<bool, VacError> {
    // Extract state needed for heartbeat
    let (sidecar_id, should_rotate) = {
        let s = state.read().map_err(|_| {
            VacError::InternalError("Failed to acquire state lock".to_string())
        })?;
        
        let should_rotate = s.should_rotate_key(rotation_interval_secs);
        (
            s.sidecar_id.clone(),
            should_rotate,
        )
    };
    
    // Rotate key if needed (before sending heartbeat)
    if should_rotate {
        let mut s = state.write().map_err(|_| {
            VacError::InternalError("Failed to acquire state lock".to_string())
        })?;
        info!("🔑 Rotating session key");
        s.rotate_session_key();
    }
    
    // Get updated public key after potential rotation
    let session_key_pub = {
        let s = state.read().map_err(|_| {
            VacError::InternalError("Failed to acquire state lock".to_string())
        })?;
        general_purpose::STANDARD.encode(s.session_key.public().to_bytes())
    };
    
    // Build heartbeat request
    let timestamp = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| VacError::InternalError(format!("System clock error: {}", e)))?
        .as_secs();
    
    let request = HeartbeatRequest {
        sidecar_id,
        session_key_pub,
        timestamp,
    };
    
    // Send heartbeat
    let client = reqwest::Client::new();
    let url = format!("{}/heartbeat", control_plane_url);
    
    let response = client
        .post(&url)
        .json(&request)
        .send()
        .await
        .map_err(|e| VacError::ProxyError(format!("Heartbeat request failed: {}", e)))?;
    
    if !response.status().is_success() {
        return Err(VacError::ProxyError(format!(
            "Heartbeat returned status: {}",
            response.status()
        )));
    }
    
    let heartbeat_response: HeartbeatResponse = response
        .json()
        .await
        .map_err(|e| VacError::InternalError(format!("Failed to parse heartbeat response: {}", e)))?;
    
    // Process response
    if !heartbeat_response.healthy {
        warn!("💓 Control Plane marked sidecar as unhealthy");
        return Ok(false); // Signal to stop heartbeat task
    }
    
    // Update revocation filter if provided
    if let Some(revoked_ids) = heartbeat_response.revoked_token_ids {
        update_revocation_filter_from_ids(state, revoked_ids)?;
    }
    
    Ok(true) // Continue heartbeat task
}

/// Update revocation filter from list of revoked token IDs
fn update_revocation_filter_from_ids(
    state: &SharedState,
    revoked_ids: Vec<[u8; 32]>,
) -> Result<(), VacError> {
    let state_guard = state.read().map_err(|_| {
        VacError::InternalError("Failed to acquire state lock".to_string())
    })?;
    
    let mut filter = state_guard.revocation_filter.write().map_err(|_| {
        VacError::InternalError("Failed to acquire revocation filter lock".to_string())
    })?;
    
    filter.update_from_ids(revoked_ids);
    
    Ok(())
}
