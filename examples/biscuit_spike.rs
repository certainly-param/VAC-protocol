// V-A-C Protocol: Biscuit Fact Extraction Proof-of-Concept
// This verifies that biscuit-auth v3+ supports Datalog queries for fact extraction
//
// To run: copy into a crate with `biscuit-auth = "3.1"` as a dependency, or
// build from the `sidecar/` directory after adding this as an example target.

use biscuit_auth::{KeyPair, Biscuit, Authorizer, builder::Fact};
use biscuit_auth::error::TokenError;

fn main() -> Result<(), TokenError> {
    // 1. SETUP: Simulating the Sidecar minting a Receipt
    let sidecar_key = KeyPair::new();

    // biscuit-auth v3: builder() takes no arguments; key is passed to build()
    let mut builder = Biscuit::builder();
    
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

    let receipt_biscuit = builder.build(&sidecar_key)?;
    println!("✅ Receipt Minted");

    // ---------------------------------------------------------

    // 2. VERIFICATION: Simulating the Sidecar reading the Receipt later
    // Create a fresh authorizer and load the receipt token into it
    let mut authorizer = Authorizer::new();
    authorizer.add_token(&receipt_biscuit)?;

    // 3. THE CRITICAL STEP: Querying Data back into Rust
    // We write a Datalog rule to select the variables we want.
    // biscuit-auth v3: query_all returns typed tuples.
    let query = "receipt_data($op, $id, $ts) <- prior_event($op, $id, $ts)";
    
    let results: Vec<(String, String, i64)> = authorizer.query_all(query)?;

    // 4. EXTRACTION: Loop through results
    for (op, correlation_id, timestamp) in &results {
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
