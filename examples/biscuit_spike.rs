// V-A-C Protocol: Biscuit Fact Extraction Proof-of-Concept
// This verifies that biscuit-auth v3+ supports Datalog queries for fact extraction

use biscuit_auth::{KeyPair, Biscuit, Authorizer, builder::Fact};
use biscuit_auth::error::TokenError;

fn main() -> Result<(), TokenError> {
    // 1. SETUP: Simulating the Sidecar minting a Receipt
    let sidecar_key = KeyPair::new();
    let root_key = KeyPair::new();

    let mut builder = Biscuit::builder(&sidecar_key);
    
    // The Sidecar adds facts to the receipt
    // fact: prior_event("search", "uuid-123", 1700000000)
    builder.add_fact(Fact::new(
        "prior_event".to_string(),
        vec![
            biscuit_auth::builder::string("search"),
            biscuit_auth::builder::string("uuid-123"),
            biscuit_auth::builder::int(1700000000),
        ],
    )).unwrap();

    let receipt_biscuit = builder.build()?;
    println!("✅ Receipt Minted");

    // ---------------------------------------------------------

    // 2. VERIFICATION: Simulating the Sidecar reading the Receipt later
    // We create an authorizer attached to the receipt
    let mut authorizer = receipt_biscuit.authorizer()?;
    
    // We assume the Sidecar trusts itself (verifies with its own public key)
    authorizer.add_token(&receipt_biscuit)?;

    // 3. THE CRITICAL STEP: Querying Data back into Rust
    // We write a Datalog rule to select the variables we want
    let query = "receipt_data($op, $id, $ts) <- prior_event($op, $id, $ts)";
    
    let result = authorizer.query(query)?;

    // 4. EXTRACTION: Loop through results
    for term in result {
        // Terms come back as Datalog types, we convert them to Rust types
        let op: String = term[0].to_string(); // "search"
        let correlation_id: String = term[1].to_string(); // "uuid-123"
        let timestamp: i64 = term[2].as_i64().unwrap(); // 1700000000

        println!("🔍 Extracted Fact:");
        println!("   Operation: {}", op);
        println!("   Correlation ID: {}", correlation_id);
        println!("   Timestamp: {}", timestamp);

        // Verification Logic (Simulated)
        if correlation_id == "uuid-123" {
            println!("✅ Correlation ID Match");
        }
    }

    Ok(())
}
