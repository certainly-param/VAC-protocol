// Simple script to generate a test Ed25519 key pair for V-A-C sidecar
// Run with: cargo run --example generate_test_keys

use biscuit_auth::KeyPair;
use hex;

fn main() {
    // Generate a new Ed25519 key pair using biscuit-auth (same as sidecar uses)
    let keypair = KeyPair::new();
    
    // Get the public key bytes (32 bytes)
    let public_key_bytes = keypair.public().to_bytes();
    
    // Get the private key bytes (64 bytes: 32 bytes secret + 32 bytes public)
    // For ed25519-dalek, we need just the secret part (first 32 bytes)
    // But biscuit-auth KeyPair doesn't expose the raw secret easily
    // So we'll show how to extract it if needed, but for config we only need public key
    let public_key_hex = hex::encode(public_key_bytes);
    
    println!("==========================================");
    println!("V-A-C Test Key Pair Generated");
    println!("==========================================");
    println!();
    println!("PUBLIC KEY (use in config.toml as root_public_key):");
    println!("{}", public_key_hex);
    println!();
    println!("NOTE: The private key is internal to the KeyPair.");
    println!("To sign Root Biscuits, use:");
    println!("  let keypair = KeyPair::new();");
    println!("  let biscuit = Biscuit::builder()...build(&keypair)?;");
    println!();
    println!("For testing, you can recreate the keypair from the public key");
    println!("by storing both keys, or regenerate a new pair each time.");
    println!();
    println!("==========================================");
    println!("Config Example:");
    println!("==========================================");
    println!();
    println!("[sidecar]");
    println!("root_public_key = \"{}\"", public_key_hex);
    println!("api_key = \"your-upstream-api-key-here\"");
    println!("upstream_url = \"http://localhost:8080\"");
    println!("control_plane_url = \"http://localhost:8081\"");
    println!();
    println!("[logging]");
    println!("level = \"info\"");
    println!();
    println!("==========================================");
    println!("⚠️  WARNING: These are TEST keys!");
    println!("For production, use a secure key management system.");
    println!("==========================================");
}
