// Common test utilities

use biscuit_auth::{KeyPair, Biscuit, PublicKey};
use std::sync::Arc;
use vac_sidecar::{SidecarState, SharedState};

/// Generate a test Root Biscuit signed with the given keypair
#[allow(dead_code)]
pub fn generate_test_root_biscuit(
    root_keypair: &KeyPair,
) -> Result<Biscuit, Box<dyn std::error::Error>> {
    let builder = Biscuit::builder();
    
    // Add a permissive allow policy for Phase 1 testing
    // This allows all operations - in production, policies would be more restrictive
    // Note: In Biscuit, we add policies via the authorizer, not the token itself
    // But for testing, we can add an allow rule that will be evaluated
    // Actually, policies are added to the authorizer at evaluation time
    // So we don't need to add policies to the biscuit builder
    // The biscuit can be empty - policies are added via authorizer.add_code()
    
    let biscuit = builder.build(root_keypair)?;
    Ok(biscuit)
}

/// Create SharedState for tests with default rate-limit/replay settings.
pub fn default_test_state(
    public_key: PublicKey,
    api_key: impl Into<String>,
    upstream_url: impl Into<String>,
) -> SharedState {
    Arc::new(std::sync::RwLock::new(SidecarState::new(
        public_key,
        api_key.into(),
        upstream_url.into(),
        100,
        60,
        false,
        60,
    )))
}

/// Cleanup test environment variables
#[allow(dead_code)]
pub fn cleanup_test_env() {
    std::env::remove_var("VAC_ROOT_PUBLIC_KEY");
    std::env::remove_var("VAC_API_KEY");
    std::env::remove_var("VAC_UPSTREAM_URL");
}
