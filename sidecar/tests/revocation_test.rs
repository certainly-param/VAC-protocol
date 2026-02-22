//! Integration tests for revocation: revoke token -> heartbeat propagates -> verify rejects.

mod common;

use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path};

use vac_sidecar::{
    send_heartbeat,
    verify_root_biscuit,
    extract_token_id,
    SharedState,
};

fn root_biscuit_b64(kp: &biscuit_auth::KeyPair) -> String {
    biscuit_auth::Biscuit::builder()
        .build(kp)
        .unwrap()
        .to_base64()
        .unwrap()
}

#[tokio::test]
async fn revoked_token_rejected_after_heartbeat() {
    let mock = MockServer::start().await;
    let root_kp = biscuit_auth::KeyPair::new();
    let token_b64 = root_biscuit_b64(&root_kp);
    let token_id = extract_token_id(&token_b64).unwrap();
    let arr: Vec<u8> = token_id.iter().copied().collect();
    let rev = serde_json::json!({ "healthy": true, "revoked_token_ids": [arr] });
    let body = serde_json::to_vec(&rev).unwrap();

    Mock::given(method("POST")).and(path("/heartbeat"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&mock)
        .await;

    let state: SharedState = common::default_test_state(
        root_kp.public(),
        "api-key",
        "http://upstream.example",
    );

    let ok = send_heartbeat(&state, mock.uri().as_str(), 300).await.unwrap();
    assert!(ok);

    let filter = {
        let s = state.read().await;
        s.revocation_filter.clone()
    };
    let result = verify_root_biscuit(&token_b64, &root_kp.public(), Some(&filter));
    assert!(result.is_err());
}
