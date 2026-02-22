use axum::{
    extract::State,
    http::HeaderValue,
    response::Response,
    routing::any,
    Router,
};
use biscuit_auth::{Biscuit, Authorizer, builder::Fact}; // Added Authorizer
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use vac_sidecar::{
    Config, CliArgs, VacError,
    SidecarState, SharedState,
    extract_receipt_info, verify_receipt_expiry, verify_correlation_id_match,
    evaluate_policy, add_context_facts, add_receipt_facts, extract_adapter_hash,
    verify_root_biscuit, verify_receipt_biscuit,
    extract_facts_from_body, load_adapters_from_dir,
    extract_depth,
    verify_delegation_chain, DELEGATION_HEADER,
    Proxy,
};
use vac_sidecar::heartbeat::start_heartbeat_task;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse CLI arguments
    let cli_args = CliArgs::parse();
    
    // Load config with precedence: CLI > env > file > defaults
    let config = Config::load(&cli_args)?;
    
    // Initialize tracing with configured log level
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();
    
    tracing::info!("🛡️ V-A-C Sidecar starting...");
    tracing::info!("📡 Upstream URL: {}", config.upstream_url);
    
    let root_public_key = biscuit_auth::PublicKey::from_bytes(&config.root_public_key)
        .map_err(|e| VacError::ConfigError(format!("Invalid public key format: {}", e)))?;
    
    let state = Arc::new(tokio::sync::RwLock::new(
        SidecarState::new(
            root_public_key, 
            config.api_key, 
            config.upstream_url,
            config.rate_limit_max_requests,
            config.rate_limit_window_secs,
            config.replay_cache_enabled,
            config.replay_cache_ttl_secs,
        )
    ));

    // Phase 4.8: Start replay cache cleanup task (if enabled)
    if config.replay_cache_enabled {
        let replay_cache = {
            let s = state.read().await;
            s.replay_cache.clone()
        };
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                replay_cache.cleanup_expired();
            }
        });
    }
    
    // Optional: preload adapters from a local directory at startup.
    if let Some(dir) = &config.adapters_dir {
        let loaded = {
            let s = state.read().await;
            load_adapters_from_dir(&s.adapter_registry, dir)?
        };
        tracing::info!("🧩 Loaded {} WASM adapter(s) from {}", loaded, dir);
    }
    
    // Start heartbeat task in background
    let state_for_heartbeat = state.clone();
    let control_plane_url = config.control_plane_url.clone();
    let heartbeat_interval = config.heartbeat_interval_secs;
    let rotation_interval = config.session_key_rotation_interval_secs;
    
    tokio::spawn(async move {
        start_heartbeat_task(
            state_for_heartbeat,
            control_plane_url,
            heartbeat_interval,
            rotation_interval,
        ).await;
    });
    
    let app = Router::new()
        .route("/*path", any(vac_guard_layer))
        .with_state(state);
    
    tracing::info!("🛡️ V-A-C Sidecar listening on 0.0.0.0:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

async fn vac_guard_layer(
    State(state): State<SharedState>,
    req: axum::extract::Request, 
) -> Result<Response, VacError> {
    use tracing::{error, info, warn};
    
    let (parts, body) = req.into_parts();
    
    // Extract method and path early for logging
    let method_str = parts.method.to_string();
    let path = parts.uri.path().to_string();
    
    // B. Extract Correlation ID (before logging span) with validation
    let correlation_id = parts.headers.get("X-Correlation-ID")
        .and_then(|h| h.to_str().ok())
        .map(|s| {
            // Validate correlation ID if provided
            if !vac_sidecar::security::validate_correlation_id(s) {
                warn!(
                    correlation_id = s,
                    "Invalid correlation ID format, generating new one"
                );
                Uuid::new_v4().to_string()
            } else {
                s.to_string()
            }
        })
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    
    // Phase 4.8: Replay attack mitigation check
    {
        let s = state.read().await;
        match s.replay_cache.check_and_insert(&correlation_id) {
            Ok(true) => {
                // New correlation ID - allowed
            }
            Ok(false) => {
                // Replay detected - reject
                warn!(
                    policy_decision = "deny",
                    reason = "replay_attack_detected",
                    correlation_id = %correlation_id,
                    "Request denied: Correlation ID already used (potential replay attack)"
                );
                return Err(VacError::Deny);
            }
            Err(_) => {
                // Replay mitigation disabled - allow
            }
        }
    }
    
    // Validate headers (Phase 4.7: Input validation)
    for (name, value) in parts.headers.iter() {
        let name_str = name.as_str();
        let value_str = match value.to_str() {
            Ok(s) => s,
            Err(_) => {
                warn!(
                    header_name = name_str,
                    "Invalid header value encoding (non-UTF-8), rejecting request"
                );
                return Err(VacError::InvalidTokenFormat);
            }
        };
        
        if !vac_sidecar::security::validate_header_name(name_str) {
            warn!(
                header_name = name_str,
                "Invalid header name, rejecting request"
            );
            return Err(VacError::InvalidTokenFormat);
        }
        
        if !vac_sidecar::security::validate_header_value(value_str) {
            warn!(
                header_name = name_str,
                header_value_length = value_str.len(),
                "Invalid header value (too long or contains control chars), rejecting request"
            );
            return Err(VacError::InvalidTokenFormat);
        }
    }
    
    // Create request span with structured fields for observability
    let span = tracing::span!(
        tracing::Level::INFO,
        "request",
        correlation_id = %correlation_id,
        method = %method_str,
        path = %path
    );
    let _guard = span.enter();
    
    // Phase 4.7: Rate limiting check (before processing request)
    let sidecar_id = {
        let s = state.read().await;
        s.sidecar_id.clone()
    };
    
    {
        let s = state.read().await;
        if !s.rate_limiter.check(&sidecar_id) {
            warn!(
                policy_decision = "deny",
                reason = "rate_limit_exceeded",
                sidecar_id = %sidecar_id,
                "Request denied: Rate limit exceeded"
            );
            return Err(VacError::Deny);
        }
    }
    
    // Check lockdown mode (before processing request)
    let lockdown_mode = {
        let s = state.read().await;
        s.lockdown_mode
    };
    
    if lockdown_mode {
        // In lockdown mode, only allow read-only requests
        if !state.read().await.is_read_only(&method_str) {
            warn!(
                policy_decision = "deny",
                reason = "lockdown_mode_active",
                "Request denied: Lockdown mode active, only read-only requests allowed"
            );
            return Err(VacError::Deny); // Reject non-read-only requests
        }
        info!("Request allowed in lockdown mode (read-only)");
    }

    // A. Extract Token
    let token_str = parts.headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|t| t.to_string())
        .ok_or_else(|| {
            warn!(
                policy_decision = "deny",
                reason = "missing_token",
                "Request denied: Missing Authorization token"
            );
            VacError::MissingToken
        })?;

    // C. Verify Root Biscuit (with revocation check)
    let (user_root_key, session_key_pub, api_key, upstream_url, proxy, revocation_filter) = {
        let s = state.read().await;
        (
            s.user_root_public_key, 
            s.session_key.public(), 
            s.api_key().to_string(), // Convert SecureString to String for heartbeat
            s.upstream_url.clone(), 
            s.proxy.clone(),
            s.revocation_filter.clone()
        )
    };
    
    let root_biscuit = verify_root_biscuit(&token_str, &user_root_key, Some(&revocation_filter))
        .map_err(|e| {
            match &e {
                VacError::InvalidSignature => {
                    warn!(
                        policy_decision = "deny",
                        reason = "invalid_biscuit_signature",
                        llm_readable_error = true,
                        "Root Biscuit verification failed: Invalid signature - Agent should verify token is signed with correct root key"
                    );
                }
                _ => {
                    error!(
                        error = %e,
                        "Root Biscuit verification error"
                    );
                }
            }
            e
        })?;
    
    info!("Root Biscuit verified successfully");

    // C.1 Verify delegation chain (Phase 4.3)
    // If present, one `X-VAC-Delegation` header per hop (root → ... → current).
    let delegation_chain_b64: Vec<String> = parts
        .headers
        .get_all(DELEGATION_HEADER)
        .iter()
        .filter_map(|h| h.to_str().ok().map(|s| s.to_string()))
        .collect();
    
    if !delegation_chain_b64.is_empty() {
        info!(
            delegation_chain_length = delegation_chain_b64.len(),
            "Verifying delegation chain"
        );
    }
    
    let (delegation_chain_ids_hex, final_depth) =
        verify_delegation_chain(&user_root_key, &delegation_chain_b64, &token_str)
            .map_err(|e| {
                warn!(
                    delegation_error = %e,
                    delegation_chain_length = delegation_chain_b64.len(),
                    "Delegation chain verification failed"
                );
                e
            })?;
    
    if !delegation_chain_ids_hex.is_empty() {
        info!(
            delegation_chain_length = delegation_chain_ids_hex.len(),
            delegation_depth = final_depth,
            "Delegation chain verified successfully"
        );
    }

    // Read request body bytes now (we may need it for adapter fact extraction).
    // Note: we rebuild the request body afterwards so proxy forwarding stays identical.
    // Phase 4.7: Use security module constant for body size limit
    let body_bytes = axum::body::to_bytes(body, vac_sidecar::security::MAX_REQUEST_BODY_SIZE)
        .await
        .map_err(|e| {
            // Check if error is due to body size limit
            let error_msg = e.to_string();
            if error_msg.contains("too large") || error_msg.contains("limit") {
                warn!(
                    body_size_limit = vac_sidecar::security::MAX_REQUEST_BODY_SIZE,
                    "Request body exceeds size limit"
                );
                VacError::InvalidTokenFormat // Use InvalidTokenFormat for size violations
            } else {
                VacError::InternalError(format!("Failed to read request body: {}", e))
            }
        })?;
    
    // Phase 4.7: Validate body size
    if !vac_sidecar::security::validate_body_size(body_bytes.len()) {
        warn!(
            body_size = body_bytes.len(),
            body_size_limit = vac_sidecar::security::MAX_REQUEST_BODY_SIZE,
            "Request body size validation failed"
        );
        return Err(VacError::InvalidTokenFormat);
    }

    // D. Build Authorizer 
    // We use Authorizer::new() to guarantee a clean slate.
    let mut authorizer = Authorizer::new();
    authorizer.add_token(&root_biscuit)
        .map_err(|e| VacError::InternalError(format!("Failed to add root token: {:?}", e)))?;

    // E. Verify & Add Receipt(s) 
    let receipt_count = parts.headers.get_all("X-VAC-Receipt").iter().count();
    if receipt_count > 0 {
        info!(
            receipt_count = receipt_count,
            "Verifying {} receipt(s)",
            receipt_count
        );
    }
    
    for receipt_val in parts.headers.get_all("X-VAC-Receipt") {
        let receipt_str = receipt_val.to_str().map_err(|_| {
            warn!(
                receipt_error = "invalid_format",
                "Receipt verification failed: Invalid token format"
            );
            VacError::InvalidTokenFormat
        })?;
        
        let receipt = verify_receipt_biscuit(receipt_str, &session_key_pub)
            .map_err(|e| {
                warn!(
                    receipt_error = "invalid_signature",
                    receipt_error_detail = %e,
                    "Receipt verification failed: Invalid signature"
                );
                e
            })?;
        
        let receipt_info = extract_receipt_info(&receipt)
            .map_err(|e| {
                warn!(
                    receipt_error = "extraction_failed",
                    receipt_error_detail = %e,
                    "Receipt verification failed: Failed to extract receipt info"
                );
                e
            })?;
        
        verify_receipt_expiry(receipt_info.timestamp)
            .map_err(|e| {
                warn!(
                    receipt_error = "expired",
                    receipt_timestamp = receipt_info.timestamp,
                    receipt_operation = %receipt_info.operation,
                    "Receipt verification failed: Receipt expired"
                );
                e
            })?;
        
        verify_correlation_id_match(&receipt_info.correlation_id, &correlation_id)
            .map_err(|e| {
                warn!(
                    receipt_error = "correlation_id_mismatch",
                    receipt_correlation_id = %receipt_info.correlation_id,
                    request_correlation_id = %correlation_id,
                    receipt_operation = %receipt_info.operation,
                    "Receipt verification failed: Correlation ID mismatch"
                );
                e
            })?;
        
        info!(
            receipt_operation = %receipt_info.operation,
            receipt_correlation_id = %receipt_info.correlation_id,
            receipt_timestamp = receipt_info.timestamp,
            "Receipt verified successfully"
        );
        
        // FIX: Pass the extracted info, not the token
        add_receipt_facts(&mut authorizer, &receipt_info)?;
    }

    // F. Add Context Facts (After all tokens are loaded)
    let method_str = parts.method.to_string();
    let path = parts.uri.path().to_string();
    add_context_facts(&mut authorizer, &method_str, &path, &correlation_id)?;

    // F.0 Delegation chain facts (Phase 4.3)
    // Inject as facts so policies can audit/limit based on chain.
    for id_hex in &delegation_chain_ids_hex {
        authorizer
            .add_fact(biscuit_auth::builder::Fact::new(
                "delegation_chain".to_string(),
                vec![biscuit_auth::builder::string(id_hex)],
            ))
            .map_err(|e| VacError::InternalError(format!("Failed to add delegation_chain fact: {:?}", e)))?;
    }

    // F.1 Optional WASM adapter facts (pinned by hash in the Root Biscuit)
    if let Some(adapter_hash) = extract_adapter_hash(&mut authorizer)? {
        let registry = {
            let s = state.read().await;
            s.adapter_registry.clone()
        };

        let adapter_facts = extract_facts_from_body(&adapter_hash, &body_bytes, &registry).await?;
        for af in adapter_facts {
            let fact = af.to_biscuit_fact()?;
            authorizer
                .add_fact(fact)
                .map_err(|e| VacError::InternalError(format!("Failed to add adapter fact: {:?}", e)))?;
        }
    }

    // G. Run Policy
    evaluate_policy(&mut authorizer)
        .map_err(|e| {
            // Log LLM-readable error messages for agent debugging
            match &e {
                VacError::PolicyViolation(msg) => {
                    warn!(
                        policy_decision = "deny",
                        policy_reason = %msg,
                        llm_readable_error = true,
                        "Policy violation: {} - Agent should review required facts/operations",
                        msg
                    );
                }
                _ => {
                    error!(error = %e, "Policy evaluation error");
                }
            }
            e
        })?;

    info!("Request authorized, forwarding to upstream");

    // H. Forward Request (body already read and validated — no double read)
    let response = proxy.as_ref().forward(&parts, body_bytes.clone(), &api_key, &upstream_url).await
        .map_err(|e| {
            error!(
                proxy_error = %e,
                upstream_url = %upstream_url,
                "Failed to forward request to upstream"
            );
            VacError::InternalError(format!("Proxy error: {:?}", e))
        })?;
    
    info!(
        upstream_status = response.status().as_u16(),
        "Request forwarded successfully"
    );

    // I. Mint Receipt
    if response.status().is_success() {
        let state_read = state.read().await;
        let mut builder = Biscuit::builder();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let operation = format!("{} {}", method_str, path);
        
        builder.add_fact(Fact::new(
            "prior_event".to_string(),
            vec![
                biscuit_auth::builder::string(&operation),
                biscuit_auth::builder::string(&correlation_id),
                biscuit_auth::builder::int(timestamp as i64),
            ],
        )).map_err(|e| VacError::InternalError(format!("Fact error: {:?}", e)))?;

        // Phase 4.3: Embed delegation chain into receipts (audit trail).
        for id_hex in &delegation_chain_ids_hex {
            builder
                .add_fact(Fact::new(
                    "delegation_chain".to_string(),
                    vec![biscuit_auth::builder::string(id_hex)],
                ))
                .map_err(|e| VacError::InternalError(format!("Fact error: {:?}", e)))?;
        }
        if let Some(depth) = extract_depth(&mut authorizer)? {
            builder
                .add_fact(Fact::new(
                    "depth".to_string(),
                    vec![biscuit_auth::builder::int(depth)],
                ))
                .map_err(|e| VacError::InternalError(format!("Fact error: {:?}", e)))?;
        }

        // Extract depth for logging (if available)
        let receipt_depth = extract_depth(&mut authorizer).ok().flatten().unwrap_or(0i64);
        
        let receipt_biscuit = builder.build(&state_read.session_key)
            .map_err(|e| VacError::InternalError(format!("Sign error: {:?}", e)))?;
        
        let receipt_b64 = receipt_biscuit.to_base64()
            .map_err(|e| VacError::InternalError(format!("Encode error: {:?}", e)))?;
        info!(
            receipt_operation = %operation,
            receipt_correlation_id = %correlation_id,
            receipt_timestamp = timestamp,
            receipt_depth = receipt_depth,
            delegation_chain_length = delegation_chain_ids_hex.len(),
            "Receipt minted successfully"
        );

        let (mut parts, body) = response.into_parts();
        parts.headers.insert(
            "X-VAC-Receipt", 
            HeaderValue::from_str(&receipt_b64)
                .map_err(|e| VacError::InternalError(format!("Failed to create header: {}", e)))?
        );
        return Ok(Response::from_parts(parts, body));
    }

    Ok(response)
}