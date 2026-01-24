// Common test utilities

use biscuit_auth::{KeyPair, Biscuit};

/// Generate a test Root Biscuit signed with the given keypair
pub fn generate_test_root_biscuit(
    root_keypair: &KeyPair,
) -> Result<Biscuit, Box<dyn std::error::Error>> {
    let mut builder = Biscuit::builder();
    
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

/// Cleanup test environment variables
pub fn cleanup_test_env() {
    std::env::remove_var("VAC_ROOT_PUBLIC_KEY");
    std::env::remove_var("VAC_API_KEY");
    std::env::remove_var("VAC_UPSTREAM_URL");
}
