use std::collections::HashSet;
use crate::error::VacError;

/// Revocation filter for efficient token revocation checking
/// 
/// Phase 3: Using HashSet for simplicity. In production, this should use a Bloom Filter
/// for memory efficiency (100k sessions → ~100KB vs ~3.2MB with HashSet).
/// 
/// For Phase 3, HashSet provides O(1) lookup with no false positives (simpler to debug).
pub struct RevocationFilter {
    revoked_tokens: HashSet<[u8; 32]>, // Set of revoked token IDs
}

impl RevocationFilter {
    /// Create a new revocation filter
    pub fn new() -> Self {
        Self {
            revoked_tokens: HashSet::new(),
        }
    }
    
    /// Check if a token ID is revoked
    pub fn is_revoked(&self, token_id: &[u8]) -> bool {
        if token_id.len() != 32 {
            // Invalid token ID format, reject to be safe
            return true;
        }
        
        let mut hash = [0u8; 32];
        hash.copy_from_slice(token_id);
        self.revoked_tokens.contains(&hash)
    }
    
    /// Add a token ID to the revocation list
    pub fn revoke(&mut self, token_id: &[u8]) -> Result<(), VacError> {
        if token_id.len() != 32 {
            return Err(VacError::InternalError(
                format!("Invalid token ID length: expected 32 bytes, got {}", token_id.len())
            ));
        }
        
        let mut hash = [0u8; 32];
        hash.copy_from_slice(token_id);
        self.revoked_tokens.insert(hash);
        Ok(())
    }
    
    /// Update the filter with a list of revoked token IDs (from heartbeat response)
    pub fn update_from_ids(&mut self, revoked_ids: Vec<[u8; 32]>) {
        for id in revoked_ids {
            self.revoked_tokens.insert(id);
        }
    }
    
    /// Get the number of revoked tokens
    pub fn revoked_count(&self) -> usize {
        self.revoked_tokens.len()
    }
}

impl Default for RevocationFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_filter_empty_not_revoked() {
        let f = RevocationFilter::new();
        let id = [0u8; 32];
        assert!(!f.is_revoked(&id));
        assert_eq!(f.revoked_count(), 0);
    }

    #[test]
    fn revocation_filter_revoke_then_is_revoked() {
        let mut f = RevocationFilter::new();
        let id = [1u8; 32];
        assert!(!f.is_revoked(&id));
        f.revoke(&id).unwrap();
        assert!(f.is_revoked(&id));
        assert_eq!(f.revoked_count(), 1);
    }

    #[test]
    fn revocation_filter_update_from_ids() {
        let mut f = RevocationFilter::new();
        let id1 = [1u8; 32];
        let id2 = [2u8; 32];
        f.update_from_ids(vec![id1, id2]);
        assert!(f.is_revoked(&id1));
        assert!(f.is_revoked(&id2));
        assert_eq!(f.revoked_count(), 2);
    }

    #[test]
    fn revocation_filter_revoke_invalid_length() {
        let mut f = RevocationFilter::new();
        let short = [0u8; 16];
        let err = f.revoke(&short).unwrap_err();
        assert!(matches!(err, VacError::InternalError(_)));
    }

    #[test]
    fn revocation_filter_is_revoked_invalid_length_rejects() {
        let f = RevocationFilter::new();
        let short = [0u8; 16];
        assert!(f.is_revoked(&short));
    }

    #[test]
    fn extract_token_id_deterministic() {
        let id1 = extract_token_id("abc").unwrap();
        let id2 = extract_token_id("abc").unwrap();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn extract_token_id_different_inputs_different_ids() {
        let id1 = extract_token_id("abc").unwrap();
        let id2 = extract_token_id("xyz").unwrap();
        assert_ne!(id1, id2);
    }
}

/// Extract token ID from a Root Biscuit
/// 
/// The token ID is derived from the biscuit's signature/public key.
/// For simplicity in Phase 3, we use the first 32 bytes of the base64-encoded biscuit.
pub fn extract_token_id(biscuit_base64: &str) -> Result<[u8; 32], VacError> {
    use sha2::{Sha256, Digest};
    
    // Hash the biscuit to get a consistent 32-byte ID
    let mut hasher = Sha256::new();
    hasher.update(biscuit_base64.as_bytes());
    let hash = hasher.finalize();
    
    let mut token_id = [0u8; 32];
    token_id.copy_from_slice(&hash);
    Ok(token_id)
}
