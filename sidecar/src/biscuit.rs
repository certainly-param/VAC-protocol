use biscuit_auth::{Biscuit, PublicKey};
use crate::error::VacError;
use crate::revocation::{extract_token_id, RevocationFilter};
use std::sync::Arc;
use std::sync::RwLock;

/// Verify a Root Biscuit signature using the user's root public key
/// 
/// Also checks revocation filter before signature verification.
pub fn verify_root_biscuit(
    token_str: &str,
    root_public_key: &PublicKey,
    revocation_filter: Option<&Arc<RwLock<RevocationFilter>>>,
) -> Result<Biscuit, VacError> {
    // Check revocation filter first (before expensive signature verification)
    if let Some(filter) = revocation_filter {
        let token_id = extract_token_id(token_str)?;
        let is_revoked = {
            let f = filter.read().map_err(|_| {
                VacError::InternalError("Failed to acquire revocation filter lock".to_string())
            })?;
            f.is_revoked(&token_id)
        };
        
        if is_revoked {
            return Err(VacError::InvalidSignature); // Token is revoked
        }
    }
    
    // Parse and verify Biscuit signature
    // The callback receives a key ID (for multi-key scenarios) and returns the public key
    let biscuit = Biscuit::from_base64(token_str, |_key_id| {
        Ok(*root_public_key)
    })
    .map_err(|_| {
        // Provide more specific error info for debugging
        VacError::InvalidSignature // TODO: Could expose more details if needed
    })?;
    
    Ok(biscuit)
}

/// Verify a Receipt Biscuit signature using the sidecar's session public key
pub fn verify_receipt_biscuit(
    receipt_str: &str,
    session_public_key: &PublicKey,
) -> Result<Biscuit, VacError> {
    // Parse and verify Receipt signature
    let receipt = Biscuit::from_base64(receipt_str, |_| {
        Ok(*session_public_key)
    })
    .map_err(|_| VacError::InvalidSignature)?;
    
    Ok(receipt)
}
