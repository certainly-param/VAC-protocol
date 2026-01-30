mod common;

use axum::{routing::any, Router};
use biscuit_auth::{Biscuit, KeyPair};
use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path};

use vac_sidecar::{enforce_max_depth, authorize_only, add_context_facts, verify_root_biscuit, DEFAULT_MAX_DELEGATION_DEPTH};

fn build_root_biscuit_with_depth(kp: &KeyPair, depth: i64) -> Biscuit {
    let mut builder = Biscuit::builder();
    builder
        .add_fact(biscuit_auth::builder::Fact::new(
            "depth".to_string(),
            vec![biscuit_auth::builder::int(depth)],
        ))
        .unwrap();
    builder.build(kp).unwrap()
}

#[tokio::test]
async fn test_delegation_depth_over_limit_denied() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server)
        .await;

    let root_keypair = KeyPair::new();
    let state = common::default_test_state(root_keypair.public(), "k", mock_server.uri());

    // Build a minimal app using the main vac_guard_layer (so we exercise real enforcement).
    // We can't import vac_guard_layer directly (private), so we call through the binary by
    // reusing the same handler is not possible here. Instead, we replicate a minimal handler
    // that calls into the same exported policy evaluation stack.
    async fn handler(
        axum::extract::State(state): axum::extract::State<vac_sidecar::SharedState>,
        req: axum::extract::Request,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        use biscuit_auth::Authorizer;
        use vac_sidecar::VacError;

        let (parts, body) = req.into_parts();
        let _ = body;

        let token_str = match parts.headers.get("Authorization") {
            Some(h) => match h.to_str().ok().and_then(|s| s.strip_prefix("Bearer ")) {
                Some(t) => t.to_string(),
                None => return VacError::InvalidTokenFormat.into_response(),
            },
            None => return VacError::MissingToken.into_response(),
        };

        let user_root_key = { state.read().unwrap().user_root_public_key };
        let root_biscuit = match verify_root_biscuit(&token_str, &user_root_key, None) {
            Ok(b) => b,
            Err(e) => return e.into_response(),
        };

        let mut authorizer = Authorizer::new();
        if let Err(e) = authorizer.add_token(&root_biscuit) {
            return VacError::InternalError(format!("Failed to add root token: {:?}", e)).into_response();
        }

        // Deny rule first (policy order matters: first match wins).
        if let Err(e) = enforce_max_depth(&mut authorizer, DEFAULT_MAX_DELEGATION_DEPTH) {
            return e.into_response();
        }
        let _ = authorizer.add_code("allow if true;");
        if let Err(e) = add_context_facts(&mut authorizer, "GET", "/test", "cid") {
            return e.into_response();
        }

        match authorize_only(&mut authorizer) {
            Ok(()) => (axum::http::StatusCode::OK, "OK").into_response(),
            Err(e) => e.into_response(),
        }
    }

    let app: Router = Router::new()
        .route("/*path", any(handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });

    let token = build_root_biscuit_with_depth(&root_keypair, 6).to_base64().unwrap();
    let url = format!("http://{}{}", addr, "/test");
    let resp = reqwest::Client::new()
        .request(reqwest::Method::GET, &url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 403);
}

