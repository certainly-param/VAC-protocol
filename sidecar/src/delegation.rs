use biscuit_auth::{Authorizer, Biscuit, PublicKey};
use biscuit_auth::builder::{BlockBuilder, Fact};

use crate::error::VacError;
use crate::revocation::extract_token_id;

/// Default maximum delegation depth.
pub const DEFAULT_MAX_DELEGATION_DEPTH: i64 = 5;

/// Header carrying the delegation chain (one biscuit per header, ordered).
///
/// Convention:
/// - Request includes N headers named `X-VAC-Delegation`, in order from root → ... → current.
/// - The last token in the chain MUST match the token in `Authorization: Bearer ...`.
pub const DELEGATION_HEADER: &str = "X-VAC-Delegation";

/// Extract the declared delegation depth from the token facts.
///
/// Convention (VAC model v4):
/// - Root (and delegated) Biscuits may include a fact `depth(N)`.
/// - Delegation increments the depth by 1 when minting a delegated token.
///
/// Returns `Ok(None)` if the token does not declare a depth.
pub fn extract_depth(authorizer: &mut Authorizer) -> Result<Option<i64>, VacError> {
    let query = "depth_value($d) <- depth($d)";
    let result: Vec<(i64,)> = authorizer
        .query(query)
        .map_err(|e| VacError::InternalError(format!("Failed to query depth: {:?}", e)))?;

    Ok(result.first().map(|(d,)| *d))
}

/// Add a global deny rule enforcing max delegation depth.
///
/// Model rule:
/// `deny if depth($d), $d > 5;`
pub fn enforce_max_depth(authorizer: &mut Authorizer, max_depth: i64) -> Result<(), VacError> {
    let code = format!("deny if depth($d), $d > {};", max_depth);
    authorizer
        .add_code(&code)
        .map_err(|e| VacError::InternalError(format!("Failed to add delegation deny rule: {:?}", e)))?;
    Ok(())
}

/// Create a delegated (attenuated) Biscuit by appending a block that increments depth.
///
/// This is intended to be used by a **token issuer / delegator** (e.g. Control Plane),
/// not necessarily by the sidecar.
pub fn create_delegated_token(parent: &Biscuit, new_depth: i64) -> Result<Biscuit, VacError> {
    let mut block = BlockBuilder::new();
    block
        .add_fact(Fact::new(
            "depth".to_string(),
            vec![biscuit_auth::builder::int(new_depth)],
        ))
        .map_err(|e| VacError::InternalError(format!("Failed to add depth fact: {:?}", e)))?;

    parent
        .append(block)
        .map_err(|e| VacError::InternalError(format!("Failed to append delegation block: {:?}", e)))
}

/// Verify a delegation chain and return ordered token IDs (hex), plus the final depth.
///
/// Verification:
/// - Each token must verify under the provided root public key.
/// - Each token must contain exactly one `depth(N)` fact.
/// - Depth must be strictly increasing by 1 starting at 0.
/// - The last token's token-id must match the Authorization token-id.
pub fn verify_delegation_chain(
    root_public_key: &PublicKey,
    chain_tokens_b64: &[String],
    authorization_token_b64: &str,
) -> Result<(Vec<String>, i64), VacError> {
    if chain_tokens_b64.is_empty() {
        // No chain provided: treat as direct root token (depth may still exist).
        // Caller can decide whether to inject any chain facts.
        let token_id_hex = hex::encode(extract_token_id(authorization_token_b64)?);
        return Ok((vec![token_id_hex], 0));
    }

    let auth_id = extract_token_id(authorization_token_b64)?;
    let mut expected_depth: i64 = 0;
    let mut ids: Vec<String> = Vec::with_capacity(chain_tokens_b64.len());

    for (idx, t) in chain_tokens_b64.iter().enumerate() {
        let biscuit = Biscuit::from_base64(t, |_key_id| Ok(*root_public_key))
            .map_err(|_| VacError::InvalidSignature)?;

        let mut a = biscuit
            .authorizer()
            .map_err(|_| VacError::InvalidSignature)?;
        let depth = extract_depth(&mut a)?
            .ok_or_else(|| VacError::PolicyViolation("Delegation token missing depth(N) fact".into()))?;

        if depth != expected_depth {
            return Err(VacError::PolicyViolation(format!(
                "Invalid delegation depth at index {}: expected {}, got {}",
                idx, expected_depth, depth
            )));
        }
        expected_depth += 1;

        let id_hex = hex::encode(extract_token_id(t)?);
        ids.push(id_hex);
    }

    // Must end at Authorization token - verify it matches and has correct depth
    let last_b64 = chain_tokens_b64.last().ok_or(VacError::Deny)?;
    let last_id = extract_token_id(last_b64)?;
    if last_id != auth_id {
        return Err(VacError::PolicyViolation(
            "Delegation chain does not end in Authorization token".into(),
        ));
    }

    // Verify Authorization token has the expected depth
    let auth_biscuit = Biscuit::from_base64(authorization_token_b64, |_key_id| Ok(*root_public_key))
        .map_err(|_| VacError::InvalidSignature)?;
    let mut auth_authorizer = auth_biscuit
        .authorizer()
        .map_err(|_| VacError::InvalidSignature)?;
    let auth_depth = extract_depth(&mut auth_authorizer)?
        .ok_or_else(|| VacError::PolicyViolation("Authorization token missing depth(N) fact".into()))?;
    
    if auth_depth != expected_depth {
        return Err(VacError::PolicyViolation(format!(
            "Authorization token depth mismatch: expected {}, got {}",
            expected_depth, auth_depth
        )));
    }

    // Add the Authorization token ID to the chain
    ids.push(hex::encode(auth_id));

    Ok((ids, expected_depth))
}

