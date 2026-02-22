use biscuit_auth::{KeyPair, PublicKey};
use std::sync::Arc;
use std::time::SystemTime;
use crate::proxy::AxumProxy;
use crate::revocation::RevocationFilter;
use crate::adapter::AdapterRegistry;
use crate::security::SecureString;
use crate::rate_limit::RateLimiter;
use crate::replay_cache::ReplayCache;

/// Sidecar state (Orange Zone - Semi-Trusted)
/// 
/// This holds the trusted state that the Sidecar needs to operate:
/// - Session key: Ephemeral key pair for signing receipts
/// - User root public key: Public key for verifying Root Biscuits
/// - API key: Key to inject into upstream requests
/// - Proxy: HTTP proxy instance for forwarding requests
/// - Upstream URL: Base URL for upstream API
/// - Heartbeat state: Health status and failure tracking
/// - Revocation filter: Bloom filter for revoked tokens
pub struct SidecarState {
    pub session_key: KeyPair,
    pub user_root_public_key: PublicKey,
    pub api_key: SecureString, // Secure memory for API key
    pub proxy: Arc<AxumProxy>,
    pub upstream_url: String,
    pub sidecar_id: String,
    // Heartbeat state
    pub heartbeat_healthy: bool,
    pub heartbeat_failure_count: u32,
    pub lockdown_mode: bool,
    pub last_heartbeat: SystemTime,
    pub last_key_rotation: SystemTime,
    // Revocation
    pub revocation_filter: Arc<std::sync::RwLock<RevocationFilter>>,
    // WASM adapters
    pub adapter_registry: AdapterRegistry,
    // Rate limiting
    pub rate_limiter: RateLimiter,
    // Phase 4.8: Replay attack mitigation
    pub replay_cache: ReplayCache,
}

/// Shared state for use across async tasks
pub type SharedState = Arc<tokio::sync::RwLock<SidecarState>>;

impl SidecarState {
    /// Create new SidecarState with generated session key
    pub fn new(
        user_root_public_key: PublicKey,
        api_key: String,
        upstream_url: String,
        rate_limit_max_requests: u32,
        rate_limit_window_secs: u64,
        replay_cache_enabled: bool,
        replay_cache_ttl_secs: u64,
    ) -> Self {
        let now = SystemTime::now();
        let secure_api_key = SecureString::from(api_key);
        
        // Attempt to lock API key memory (best-effort, logs warning on failure)
        crate::security::lock_string_memory(secure_api_key.as_str());
        
        Self {
            session_key: KeyPair::new(), // Generate new ephemeral session key
            user_root_public_key,
            api_key: secure_api_key,
            proxy: Arc::new(AxumProxy::new()),
            upstream_url,
            sidecar_id: uuid::Uuid::new_v4().to_string(),
            heartbeat_healthy: false, // Start as unhealthy until first heartbeat succeeds
            heartbeat_failure_count: 0,
            lockdown_mode: false,
            last_heartbeat: now,
            last_key_rotation: now,
            revocation_filter: Arc::new(std::sync::RwLock::new(RevocationFilter::new())),
            adapter_registry: AdapterRegistry::new(),
            rate_limiter: RateLimiter::new(
                rate_limit_max_requests,
                std::time::Duration::from_secs(rate_limit_window_secs),
            ),
            replay_cache: ReplayCache::new(
                std::time::Duration::from_secs(replay_cache_ttl_secs),
                replay_cache_enabled,
            ),
        }
    }
    
    /// Get API key as string reference (for use in requests)
    pub fn api_key(&self) -> &str {
        self.api_key.as_str()
    }
    
    /// Rotate session key (invalidates all existing receipts)
    pub fn rotate_session_key(&mut self) {
        self.session_key = KeyPair::new();
        self.last_key_rotation = SystemTime::now();
    }
    
    /// Check if session key needs rotation
    pub fn should_rotate_key(&self, rotation_interval_secs: u64) -> bool {
        let now = SystemTime::now();
        if let Ok(elapsed) = now.duration_since(self.last_key_rotation) {
            elapsed.as_secs() >= rotation_interval_secs
        } else {
            true // Clock went backwards, rotate to be safe
        }
    }
    
    /// Enter lockdown mode (reject all non-read-only requests)
    pub fn enter_lockdown(&mut self) {
        self.lockdown_mode = true;
    }
    
    /// Check if request should be allowed in lockdown mode
    pub fn is_read_only(&self, method: &str) -> bool {
        matches!(method, "GET" | "HEAD" | "OPTIONS")
    }
}
