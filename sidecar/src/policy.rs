use biscuit_auth::Authorizer;
use crate::error::VacError;
use crate::receipt::ReceiptInfo; // Ensure ReceiptInfo is public in receipt.rs
use crate::delegation::{enforce_max_depth, DEFAULT_MAX_DELEGATION_DEPTH};

/// Evaluate Datalog policy using Biscuit Authorizer
pub fn evaluate_policy(authorizer: &mut Authorizer) -> Result<(), VacError> {
    use tracing::{info, warn};
    
    // Global VAC policy: delegation depth must be bounded.
    // This is enforced in the authorizer (mathematical / Datalog enforcement).
    enforce_max_depth(authorizer, DEFAULT_MAX_DELEGATION_DEPTH)?;

    match authorizer.authorize() {
        Ok(_) => {
            // Log successful policy evaluation
            info!(
                policy_decision = "allow",
                "Policy evaluation: ALLOW - Request authorized"
            );
            Ok(())
        }
        Err(e) => {
            // Extract LLM-readable error message for agent debugging
            let error_message = format!("Policy evaluation failed: {:?}", e);
            
            // Log policy denial with structured fields
            warn!(
                policy_decision = "deny",
                policy_error = %error_message,
                "Policy evaluation: DENY - {}",
                error_message
            );
            
            Err(VacError::PolicyViolation(error_message))
        }
    }
}

pub fn add_context_facts(
    authorizer: &mut Authorizer,
    method: &str,
    path: &str,
    correlation_id: &str,
) -> Result<(), VacError> {
    use biscuit_auth::builder::Fact;
    
    authorizer.add_fact(Fact::new(
        "operation".to_string(),
        vec![
            biscuit_auth::builder::string(method),
            biscuit_auth::builder::string(path),
        ],
    )).map_err(|e| VacError::InternalError(format!("Failed to add operation fact: {:?}", e)))?;
    
    authorizer.add_fact(Fact::new(
        "correlation_id".to_string(),
        vec![biscuit_auth::builder::string(correlation_id)],
    )).map_err(|e| VacError::InternalError(format!("Failed to add correlation_id fact: {:?}", e)))?;
    
    Ok(())
}

/// Extract an optional WASM adapter hash from the Root Biscuit facts.
///
/// Convention (Phase 4.1):
/// - Root Biscuit may include a fact: `adapter_hash("<hex sha256>")`
/// - If present, the Sidecar will execute the pinned adapter and inject returned facts.
pub fn extract_adapter_hash(authorizer: &mut Authorizer) -> Result<Option<String>, VacError> {
    let query = "adapter_hash($h) <- adapter_hash($h)";
    let result: Vec<(String,)> = authorizer
        .query(query)
        .map_err(|e| VacError::InternalError(format!("Failed to query adapter_hash: {:?}", e)))?;

    Ok(result.first().map(|(h,)| h.clone()))
}

/// FIX: Manually inject receipt facts instead of using add_token()
/// This bypasses the "AuthorizerNotEmpty" error in biscuit-auth v3.
pub fn add_receipt_facts(
    authorizer: &mut Authorizer,
    info: &ReceiptInfo,
) -> Result<(), VacError> {
    use biscuit_auth::builder::Fact;

    // We trust this info because the Sidecar verified the Receipt signature upstream.
    // Inject: prior_event(operation, correlation_id, timestamp)
    authorizer.add_fact(Fact::new(
        "prior_event".to_string(),
        vec![
            biscuit_auth::builder::string(&info.operation),
            biscuit_auth::builder::string(&info.correlation_id),
            biscuit_auth::builder::int(info.timestamp),
        ],
    )).map_err(|e| VacError::InternalError(format!("Failed to add receipt fact: {:?}", e)))?;
    
    Ok(())
}