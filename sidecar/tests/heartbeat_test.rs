//! Integration tests for heartbeat protocol.

mod common;

use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path};

use vac_sidecar::{send_heartbeat, SharedState};

#[tokio::test]
async fn heartbeat_success_updates_state() {
    let mock = MockServer::start().await;
    Mock::given(method("POST")).and(path("/heartbeat"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "healthy": true,
                "revoked_token_ids": null
            })),
        )
        .mount(&mock)
        .await;

    let state: SharedState = common::default_test_state(
        biscuit_auth::KeyPair::new().public(),
        "api-key",
        "http://upstream.example",
    );

    let res = send_heartbeat(&state, mock.uri().as_str(), 300).await;
    assert!(res.is_ok(), "heartbeat failed: {:?}", res);
    assert_eq!(res.unwrap(), true);

    let s = state.read().unwrap();
    assert!(s.heartbeat_healthy);
    assert_eq!(s.heartbeat_failure_count, 0);
}

#[tokio::test]
async fn heartbeat_failure_increments_count() {
    let mock = MockServer::start().await;
    Mock::given(method("POST")).and(path("/heartbeat"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;

    let state: SharedState = common::default_test_state(
        biscuit_auth::KeyPair::new().public(),
        "api-key",
        "http://upstream.example",
    );

    let _ = send_heartbeat(&state, mock.uri().as_str(), 300).await;

    let s = state.read().unwrap();
    assert!(!s.heartbeat_healthy);
    assert_eq!(s.heartbeat_failure_count, 1);
}
