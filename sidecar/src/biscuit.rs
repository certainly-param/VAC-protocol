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

#[cfg(test)]
mod tests {
    use super::*;
    use biscuit_auth::KeyPair;
    use std::sync::{Arc, RwLock};

    fn test_keypair() -> KeyPair {
        KeyPair::new()
    }

    #[test]
    fn verify_root_biscuit_valid_token_correct_key() {
        let kp = test_keypair();
        let biscuit = Biscuit::builder().build(&kp).unwrap();
        let token = biscuit.to_base64().unwrap();
        let pk = kp.public();
        let result = verify_root_biscuit(&token, &pk, None);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_root_biscuit_valid_token_wrong_key() {
        let kp = test_keypair();
        let other = KeyPair::new();
        let biscuit = Biscuit::builder().build(&kp).unwrap();
        let token = biscuit.to_base64().unwrap();
        let wrong_pk = other.public();
        let result = verify_root_biscuit(&token, &wrong_pk, None);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::error::VacError::InvalidSignature)));
    }

    #[test]
    fn verify_root_biscuit_invalid_base64() {
        let kp = test_keypair();
        let pk = kp.public();
        let result = verify_root_biscuit("!!!invalid-base64!!!", &pk, None);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::error::VacError::InvalidSignature)));
    }

    #[test]
    fn verify_root_biscuit_revoked_token() {
        let kp = test_keypair();
        let biscuit = Biscuit::builder().build(&kp).unwrap();
        let token = biscuit.to_base64().unwrap();
        let pk = kp.public();
        let token_id = crate::revocation::extract_token_id(&token).unwrap();
        let mut filter = RevocationFilter::new();
        filter.revoke(&token_id).unwrap();
        let filter = Arc::new(RwLock::new(filter));
        let result = verify_root_biscuit(&token, &pk, Some(&filter));
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::error::VacError::InvalidSignature)));
    }

    #[test]
    fn verify_receipt_biscuit_valid_correct_key() {
        let kp = test_keypair();
        let receipt = Biscuit::builder().build(&kp).unwrap();
        let receipt_b64 = receipt.to_base64().unwrap();
        let pk = kp.public();
        let result = verify_receipt_biscuit(&receipt_b64, &pk);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_receipt_biscuit_wrong_key() {
        let kp = test_keypair();
        let other = KeyPair::new();
        let receipt = Biscuit::builder().build(&kp).unwrap();
        let receipt_b64 = receipt.to_base64().unwrap();
        let wrong_pk = other.public();
        let result = verify_receipt_biscuit(&receipt_b64, &wrong_pk);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::error::VacError::InvalidSignature)));
    }
}
