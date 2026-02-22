mod common;

use axum::{routing::any, Router};
use biscuit_auth::{Biscuit, KeyPair};
use biscuit_auth::builder::Fact;
use uuid::Uuid;
use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path};

use vac_sidecar::{SharedState, DELEGATION_HEADER};

fn root_biscuit_with_depth(kp: &KeyPair, depth: i64) -> Biscuit {
    let mut builder = Biscuit::builder();
    builder
        .add_fact(Fact::new(
            "depth".to_string(),
            vec![biscuit_auth::builder::int(depth)],
        ))
        .unwrap();
    builder.build(kp).unwrap()
}

async fn create_app(state: SharedState) -> Router {
    // Use the permissive router logic from integration_test.rs style, but call into the real library.
    async fn handler(
        axum::extract::State(state): axum::extract::State<SharedState>,
        req: axum::extract::Request,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        use biscuit_auth::Authorizer;
        use vac_sidecar::*;

        let (parts, body) = req.into_parts();
        let _ = body;

        let token_str = match parts.headers.get("Authorization") {
            Some(h) => match h.to_str().ok().and_then(|s| s.strip_prefix("Bearer ")) {
                Some(t) => t.to_string(),
                None => return VacError::InvalidTokenFormat.into_response(),
            },
            None => return VacError::MissingToken.into_response(),
        };

        let correlation_id = parts
            .headers
            .get("X-Correlation-ID")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let user_root_key = { state.read().await.user_root_public_key };
        let root_biscuit = match verify_root_biscuit(&token_str, &user_root_key, None) {
            Ok(b) => b,
            Err(e) => return e.into_response(),
        };

        // Verify chain if present
        let chain: Vec<String> = parts
            .headers
            .get_all(DELEGATION_HEADER)
            .iter()
            .filter_map(|h| h.to_str().ok().map(|s| s.to_string()))
            .collect();
        if !chain.is_empty() {
            // Verify delegation chain - return error if invalid
            if let Err(e) = verify_delegation_chain(&user_root_key, &chain, &token_str) {
                return e.into_response();
            }
        }

        let mut authorizer = Authorizer::new();
        let _ = authorizer.add_token(&root_biscuit);
        let _ = add_context_facts(&mut authorizer, "GET", "/test", &correlation_id);
        let _ = authorizer.add_code("allow if true;");

        match evaluate_policy(&mut authorizer) {
            Ok(()) => (axum::http::StatusCode::OK, "OK").into_response(),
            Err(e) => e.into_response(),
        }
    }

    Router::new().route("/*path", any(handler)).with_state(state)
}

#[tokio::test]
async fn test_valid_delegation_chain_allows() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server)
        .await;

    let root_keypair = KeyPair::new();
    let state = common::default_test_state(root_keypair.public(), "k", mock_server.uri());
    let app = create_app(state).await;

    let t0 = root_biscuit_with_depth(&root_keypair, 0);
    let t1 = root_biscuit_with_depth(&root_keypair, 1);
    let t2 = root_biscuit_with_depth(&root_keypair, 2);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });

    let token = t2.to_base64().unwrap();
    let resp = reqwest::Client::new()
        .get(format!("http://{}/test", addr))
        .header("Authorization", format!("Bearer {}", token))
        .header("X-Correlation-ID", Uuid::new_v4().to_string())
        .header(DELEGATION_HEADER, t0.to_base64().unwrap())
        .header(DELEGATION_HEADER, t1.to_base64().unwrap())
        .header(DELEGATION_HEADER, t2.to_base64().unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn test_invalid_delegation_chain_denies() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server)
        .await;

    let root_keypair = KeyPair::new();
    let state = common::default_test_state(root_keypair.public(), "k", mock_server.uri());
    let app = create_app(state).await;

    let t0 = root_biscuit_with_depth(&root_keypair, 0);
    let t_bad = root_biscuit_with_depth(&root_keypair, 2);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });

    let token = t_bad.to_base64().unwrap();
    let resp = reqwest::Client::new()
        .get(format!("http://{}/test", addr))
        .header("Authorization", format!("Bearer {}", token))
        .header("X-Correlation-ID", Uuid::new_v4().to_string())
        .header(DELEGATION_HEADER, t0.to_base64().unwrap())
        .header(DELEGATION_HEADER, t_bad.to_base64().unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 403);
}

