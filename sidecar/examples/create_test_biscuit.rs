// Helper script to create a test Root Biscuit for testing
// Run with: cargo run --example create_test_biscuit

use biscuit_auth::KeyPair;
use hex;

fn main() {
    // Generate or use existing keypair
    // For testing, we'll generate a new one and show both keys
    let keypair = KeyPair::new();
    let public_key_bytes = keypair.public().to_bytes();
    let public_key_hex = hex::encode(public_key_bytes);
    
    // Create a simple Root Biscuit
    let mut builder = biscuit_auth::Biscuit::builder();
    builder
        .add_fact(biscuit_auth::builder::Fact::new(
            "test".to_string(),
            vec![biscuit_auth::builder::string("value")],
        ))
        .unwrap();
    
    // Add a permissive policy for testing
    builder.add_code("allow if true;").unwrap();
    
    let biscuit = builder.build(&keypair).unwrap();
    let biscuit_token = biscuit.to_base64().unwrap();
    
    println!("==========================================");
    println!("Test Root Biscuit Created");
    println!("==========================================");
    println!();
    println!("PUBLIC KEY (use in config.toml):");
    println!("{}", public_key_hex);
    println!();
    println!("ROOT BISCUIT TOKEN (use in Authorization header):");
    println!("{}", biscuit_token);
    println!();
    println!("==========================================");
    println!("Test Command:");
    println!("==========================================");
    println!();
    println!("curl -X POST http://localhost:3000/charge -H \"Authorization: Bearer {}\" -H \"Content-Type: application/json\" -d \"{{\\\"amount\\\": 5000, \\\"currency\\\": \\\"usd\\\"}}\"", biscuit_token);
    println!();
}
