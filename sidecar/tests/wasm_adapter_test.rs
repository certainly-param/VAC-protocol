use sha2::{Digest, Sha256};
use vac_sidecar::{AdapterRegistry, extract_facts_from_body, load_adapter_from_url};
use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path};

#[tokio::test]
async fn test_wasm_adapter_extract_facts_constant_json() {
    // A tiny WASM module that exports:
    // - memory
    // - extract_facts(ptr,len) -> i32
    // And returns a pointer to a NUL-terminated JSON string in memory.
    let wat = r#"
    (module
      (memory (export "memory") 1)
      (data (i32.const 0) "[{\"fact\":\"amount\",\"args\":[\"350\"]},{\"fact\":\"currency\",\"args\":[\"USD\"]}]\00")
      (func (export "extract_facts") (param i32 i32) (result i32)
        (i32.const 0))
    )
    "#;

    let wasm_bytes = wat::parse_str(wat).expect("wat parse");
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(&wasm_bytes);
        hex::encode(hasher.finalize())
    };

    let registry = AdapterRegistry::new();
    registry
        .load_adapter(&wasm_bytes, &hash)
        .expect("load adapter");

    let body = br#"{"ignored":true}"#;
    let facts = extract_facts_from_body(&hash, body, &registry)
        .await
        .expect("extract facts");

    assert_eq!(facts.len(), 2);
    assert_eq!(facts[0].fact_name, "amount");
    assert_eq!(facts[0].args, vec!["350".to_string()]);
    assert_eq!(facts[1].fact_name, "currency");
    assert_eq!(facts[1].args, vec!["USD".to_string()]);
}

#[tokio::test]
async fn test_load_adapter_from_url_and_extract_facts() {
    let wat = r#"
    (module
      (memory (export "memory") 1)
      (data (i32.const 0) "[{\"fact\":\"k\",\"args\":[\"v\"]}]\00")
      (func (export "extract_facts") (param i32 i32) (result i32)
        (i32.const 0))
    )
    "#;
    let wasm_bytes = wat::parse_str(wat).expect("wat parse");
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(&wasm_bytes);
        hex::encode(hasher.finalize())
    };

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/adapter.wasm"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(wasm_bytes.clone()))
        .mount(&mock_server)
        .await;

    let registry = AdapterRegistry::new();
    let url = format!("{}/adapter.wasm", mock_server.uri());
    load_adapter_from_url(&registry, &url, &hash).await.expect("load from url");

    let facts = extract_facts_from_body(&hash, b"{}", &registry).await.expect("extract facts");
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].fact_name, "k");
    assert_eq!(facts[0].args, vec!["v".to_string()]);
}

#[tokio::test]
async fn test_load_adapter_from_url_hash_mismatch_fails() {
    let wat = r#"
    (module
      (memory (export "memory") 1)
      (data (i32.const 0) "[]\00")
      (func (export "extract_facts") (param i32 i32) (result i32)
        (i32.const 0))
    )
    "#;
    let wasm_bytes = wat::parse_str(wat).expect("wat parse");

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/adapter.wasm"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(wasm_bytes))
        .mount(&mock_server)
        .await;

    let registry = AdapterRegistry::new();
    let url = format!("{}/adapter.wasm", mock_server.uri());
    let err = load_adapter_from_url(&registry, &url, "deadbeef").await.unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("hash mismatch") || msg.contains("mismatch"));
}

