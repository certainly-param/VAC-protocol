use biscuit_auth::Biscuit;
use crate::error::VacError;
use std::time::{SystemTime, UNIX_EPOCH};

/// Receipt expiry time: 5 minutes (300 seconds)
const RECEIPT_EXPIRY_SECONDS: u64 = 300;
/// Grace period for clock skew: 30 seconds
const CLOCK_SKEW_GRACE_SECONDS: u64 = 30;

/// Information extracted from a receipt Biscuit
/// 
/// Note: Datalog uses i64 for integers, not u64
#[derive(Debug, Clone)]
pub struct ReceiptInfo {
    pub operation: String,
    pub correlation_id: String,
    pub timestamp: i64, // Datalog uses i64 for integers
}

/// Extract receipt information from a Biscuit using Datalog queries
/// 
/// # Implementation
/// Biscuit doesn't expose token payload like JWT. We query it using Datalog.
/// The official fix for biscuit-auth v3.x API: explicitly handle Term enum mapping
/// to satisfy Rust's static type requirements.
pub fn extract_receipt_info(
    receipt: &Biscuit,
) -> Result<ReceiptInfo, VacError> {
    // 1. Create Authorizer from the receipt
    // Note: receipt.authorizer() already includes the receipt token, so we don't need to add it again
    let mut authorizer = receipt.authorizer()
        .map_err(|_| VacError::InvalidSignature)?;

    // 3. Define the Query
    // We project the fields into a temporary rule 'receipt_data'
    let query = "receipt_data($op, $id, $ts) <- prior_event($op, $id, $ts)";

    // 4. Execute Query
    // The query API returns tuples directly (String, String, i64) for the three variables
    // Based on official biscuit-auth docs: query returns Vec<(T1, T2, T3)> for 3-arity queries
    let result: Vec<(String, String, i64)> = authorizer.query(query)
        .map_err(|e| VacError::ReceiptError(format!("Query failed: {:?}", e)))?;

    // 5. Extract Data
    if result.is_empty() {
        return Err(VacError::ReceiptError("No valid 'prior_event' fact found in receipt".to_string()));
    }

    // We take the first matching row (tuple)
    let (operation, correlation_id, timestamp) = &result[0];

    Ok(ReceiptInfo {
        operation: operation.clone(),
        correlation_id: correlation_id.clone(),
        timestamp: *timestamp,
    })
}

/// Verify receipt has not expired
/// 
/// Receipts are valid for RECEIPT_EXPIRY_SECONDS (5 minutes) with
/// a grace period of CLOCK_SKEW_GRACE_SECONDS (30 seconds) for clock skew.
/// 
/// Note: timestamp is i64 (Datalog format), converted to u64 for comparison
pub fn verify_receipt_expiry(timestamp: i64) -> Result<(), VacError> {
    // Convert i64 timestamp to u64 (Datalog uses i64, but we store as u64 internally)
    let timestamp_u64 = timestamp as u64;
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| VacError::InternalError(format!("System clock error: {}", e)))?
        .as_secs();
    
    let expiry_time = timestamp_u64 + RECEIPT_EXPIRY_SECONDS + CLOCK_SKEW_GRACE_SECONDS;
    
    if now > expiry_time {
        return Err(VacError::ReceiptExpired);
    }
    
    Ok(())
}

/// Verify receipt correlation ID matches the request correlation ID
pub fn verify_correlation_id_match(
    receipt_cid: &str,
    request_cid: &str,
) -> Result<(), VacError> {
    if receipt_cid != request_cid {
        return Err(VacError::CorrelationIdMismatch);
    }
    
    Ok(())
}
