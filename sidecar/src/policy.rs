use biscuit_auth::Authorizer;
use crate::error::VacError;
use crate::receipt::ReceiptInfo; // Ensure ReceiptInfo is public in receipt.rs
use crate::delegation::{enforce_max_depth, DEFAULT_MAX_DELEGATION_DEPTH};

/// Run authorizer.authorize() and map result to VacError. Use when you have
/// already added global deny rules (e.g. enforce_max_depth) and allow rules.
pub fn authorize_only(authorizer: &mut Authorizer) -> Result<(), VacError> {
    use tracing::{info, warn};
    match authorizer.authorize() {
        Ok(_) => {
            info!(policy_decision = "allow", "Policy evaluation: ALLOW - Request authorized");
            Ok(())
        }
        Err(e) => {
            let msg = format!("Policy evaluation failed: {:?}", e);
            warn!(policy_decision = "deny", policy_error = %msg, "Policy evaluation: DENY - {}", msg);
            Err(VacError::PolicyViolation(msg))
        }
    }
}

/// Evaluate Datalog policy using Biscuit Authorizer
pub fn evaluate_policy(authorizer: &mut Authorizer) -> Result<(), VacError> {
    // Global VAC policy: delegation depth must be bounded.
    enforce_max_depth(authorizer, DEFAULT_MAX_DELEGATION_DEPTH)?;
    authorize_only(authorizer)
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

#[cfg(test)]
mod tests {
    use super::*;
    use biscuit_auth::{Authorizer, Biscuit, KeyPair};
    use crate::receipt::ReceiptInfo;

    fn root_biscuit_no_depth() -> Biscuit {
        let kp = KeyPair::new();
        Biscuit::builder().build(&kp).unwrap()
    }

    #[test]
    fn evaluate_policy_allow_if_true() {
        let root = root_biscuit_no_depth();
        let mut auth = Authorizer::new();
        auth.add_token(&root).unwrap();
        auth.add_code("allow if true;").unwrap();
        assert!(evaluate_policy(&mut auth).is_ok());
    }

    #[test]
    fn evaluate_policy_deny_if_true() {
        let root = root_biscuit_no_depth();
        let mut auth = Authorizer::new();
        auth.add_token(&root).unwrap();
        auth.add_code("deny if true;").unwrap();
        auth.add_code("allow if true;").unwrap(); // allow too, but deny wins
        let r = evaluate_policy(&mut auth);
        assert!(r.is_err());
        assert!(matches!(r, Err(VacError::PolicyViolation(_))));
    }

    #[test]
    fn evaluate_policy_no_allow_denied() {
        let root = root_biscuit_no_depth();
        let mut auth = Authorizer::new();
        auth.add_token(&root).unwrap();
        // no allow rule
        let r = evaluate_policy(&mut auth);
        assert!(r.is_err());
        assert!(matches!(r, Err(VacError::PolicyViolation(_))));
    }

    #[test]
    fn add_context_facts_and_allow_operation() {
        let root = root_biscuit_no_depth();
        let mut auth = Authorizer::new();
        auth.add_token(&root).unwrap();
        add_context_facts(&mut auth, "GET", "/search", "cid-1").unwrap();
        auth.add_code(r#"allow if operation("GET", "/search");"#).unwrap();
        assert!(evaluate_policy(&mut auth).is_ok());
    }

    #[test]
    fn evaluate_policy_depth_over_limit_denied() {
        let kp = biscuit_auth::KeyPair::new();
        let mut b = biscuit_auth::Biscuit::builder();
        b.add_fact(biscuit_auth::builder::Fact::new(
            "depth".to_string(),
            vec![biscuit_auth::builder::int(6)],
        ))
        .unwrap();
        let root = b.build(&kp).unwrap();
        let mut auth = Authorizer::new();
        auth.add_token(&root).unwrap();
        enforce_max_depth(&mut auth, crate::delegation::DEFAULT_MAX_DELEGATION_DEPTH).unwrap();
        auth.add_code("allow if true;").unwrap();
        let r = super::authorize_only(&mut auth);
        assert!(r.is_err());
        assert!(matches!(r, Err(VacError::PolicyViolation(_))));
    }

    #[test]
    fn add_receipt_facts_and_allow_prior_event() {
        let root = root_biscuit_no_depth();
        let info = ReceiptInfo {
            operation: "GET /search".into(),
            correlation_id: "cid-1".into(),
            timestamp: 1704067200,
        };
        let mut auth = Authorizer::new();
        auth.add_token(&root).unwrap();
        add_context_facts(&mut auth, "POST", "/charge", "cid-1").unwrap();
        add_receipt_facts(&mut auth, &info).unwrap();
        auth.add_code(
            r#"allow if operation("POST", "/charge"), prior_event($op, $cid, $ts), $op.starts_with("GET /search");"#,
        )
        .unwrap();
        assert!(evaluate_policy(&mut auth).is_ok());
    }
}