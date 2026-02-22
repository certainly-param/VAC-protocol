// Integration tests for VAC Sidecar
mod common;

// #region agent log
fn agent_log(location: &str, message: &str, data: &str, hypothesis_id: &str) {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
    let line = format!(
        r#"{{"location":"{}","message":"{}","data":{},"timestamp":{},"sessionId":"debug-session","hypothesisId":"{}"}}"#,
        location,
        message.replace('"', "\\\"").replace('\n', " "),
        data,
        ts,
        hypothesis_id
    );
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(r"c:\Users\param\Desktop\github-projects\vac\.cursor\debug.log") {
        let _ = writeln!(f, "{}", line);
    }
}
// #endregion

use axum::{
    http::{HeaderValue, Method},
    routing::any,
    Router,
};
use biscuit_auth::{Biscuit, KeyPair, Authorizer};
use uuid::Uuid;
use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path};
use std::io::Write;

use vac_sidecar::SharedState;

// -----------------------------------------------------------------------------
// SECTION 2: PERMISSIVE ROUTER (Plumbing Tests)
// -----------------------------------------------------------------------------
async fn create_permissive_router(state: SharedState) -> Router {
    async fn permissive_handler(
        axum::extract::State(state): axum::extract::State<SharedState>,
        req: axum::extract::Request,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        use vac_sidecar::*;
        use biscuit_auth::builder::Fact;
        use std::time::{SystemTime, UNIX_EPOCH};

        let (parts, body) = req.into_parts();

        // A. Extract Token & B. Correlation ID (Same as before)
        let token_str = match parts.headers.get("Authorization") {
            Some(h) => match h.to_str() {
                Ok(s) => match s.strip_prefix("Bearer ") {
                    Some(t) => t.to_string(),
                    None => return VacError::InvalidTokenFormat.into_response(),
                },
                Err(_) => return VacError::InvalidTokenFormat.into_response(),
            },
            None => return VacError::MissingToken.into_response(),
        };

        let correlation_id = parts.headers.get("X-Correlation-ID")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let (user_root_key, session_key_pub, api_key, upstream_url, proxy) = {
    let s = state.read().await;
            (s.user_root_public_key, s.session_key.public(), s.api_key.clone(), s.upstream_url.clone(), s.proxy.clone())
        };
        
        let root_biscuit = match verify_root_biscuit(&token_str, &user_root_key, None) {
            Ok(b) => b,
            Err(e) => return e.into_response(),
        };

        // FIX: Manual Authorizer Construction
        let mut authorizer = Authorizer::new();
        if let Err(e) = authorizer.add_token(&root_biscuit) {
            return VacError::InternalError(format!("Failed to add root token: {:?}", e)).into_response();
        }

        // LOAD RECEIPTS FIRST
        for receipt_val in parts.headers.get_all("X-VAC-Receipt") {
            let receipt_str = match receipt_val.to_str() {
                Ok(s) => s,
                Err(_) => return VacError::InvalidTokenFormat.into_response(),
            };
            
            let receipt = match verify_receipt_biscuit(receipt_str, &session_key_pub) {
                Ok(r) => r,
                Err(e) => return e.into_response(),
            };

            let receipt_info = match extract_receipt_info(&receipt) {
                Ok(info) => info,
                Err(e) => return e.into_response(),
            };
            
            if let Err(e) = verify_receipt_expiry(receipt_info.timestamp) {
                return e.into_response();
            }
            
            if let Err(e) = verify_correlation_id_match(&receipt_info.correlation_id, &correlation_id) {
                return e.into_response();
            }

            // FIX: Pass receipt_info instead of receipt
            if let Err(e) = add_receipt_facts(&mut authorizer, &receipt_info) {
                return e.into_response();
            }
        }

        // F. Context Facts
        let method_str = parts.method.to_string();
        let path = parts.uri.path().to_string();
        if let Err(e) = add_context_facts(&mut authorizer, &method_str, &path, &correlation_id) {
            return e.into_response();
        }

        // PERMISSIVE POLICY
        let _ = authorizer.add_code("allow if true;");

        // H. Evaluate
        if let Err(e) = evaluate_policy(&mut authorizer) {
            return e.into_response();
        }

        // I. Forward (read body bytes first to match Proxy trait)
        let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
            .await
            .unwrap_or_default();
        let response = match proxy.as_ref().forward(&parts, body_bytes, api_key.as_str(), &upstream_url).await {
            Ok(r) => r,
            Err(e) => return e.into_response(),
        };

        // J. Mint
        if response.status().is_success() {
            let state_read = state.read().await;
            let mut builder = Biscuit::builder();
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

            if let Err(e) = builder.add_fact(Fact::new(
                "prior_event".to_string(),
                vec![
                    biscuit_auth::builder::string(&format!("{} {}", method_str, path)),
                    biscuit_auth::builder::string(&correlation_id),
                    biscuit_auth::builder::int(timestamp as i64),
                ],
            )) {
                return VacError::InternalError(format!("Fact error: {:?}", e)).into_response();
            }

            let receipt_biscuit = match builder.build(&state_read.session_key) {
                Ok(b) => b,
                Err(e) => return VacError::InternalError(format!("Sign error: {:?}", e)).into_response(),
            };
            
            let receipt_b64 = match receipt_biscuit.to_base64() {
                Ok(b) => b,
                Err(e) => return VacError::InternalError(format!("Encode error: {:?}", e)).into_response(),
            };

            let (mut parts, body) = response.into_parts();
            match HeaderValue::from_str(&receipt_b64) {
                Ok(hv) => {
                    parts.headers.insert("X-VAC-Receipt", hv);
                    return axum::response::Response::from_parts(parts, body);
                }
                Err(e) => return VacError::InternalError(format!("Header error: {}", e)).into_response(),
            }
        }

        response
    }
    
    Router::new()
        .route("/*path", any(permissive_handler))
        .with_state(state)
}

// -----------------------------------------------------------------------------
// SECTION 3: STRICT ROUTER (State Gate Tests)
// -----------------------------------------------------------------------------
async fn create_strict_router(state: SharedState) -> Router {
    async fn strict_handler(
        axum::extract::State(state): axum::extract::State<SharedState>,
        req: axum::extract::Request,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        use vac_sidecar::*;
        use biscuit_auth::builder::Fact;
        use std::time::{SystemTime, UNIX_EPOCH};

        let (parts, body) = req.into_parts();

        // A. Extract Token & B. Correlation ID (Same as before)
        let token_str = match parts.headers.get("Authorization") {
            Some(h) => match h.to_str() {
                Ok(s) => match s.strip_prefix("Bearer ") {
                    Some(t) => t.to_string(),
                    None => return VacError::InvalidTokenFormat.into_response(),
                },
                Err(_) => return VacError::InvalidTokenFormat.into_response(),
            },
            None => return VacError::MissingToken.into_response(),
        };

        let correlation_id = parts.headers.get("X-Correlation-ID")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // #region agent log
        let method_str_early = parts.method.to_string();
        let path_early = parts.uri.path().to_string();
        let receipt_count = parts.headers.get_all("X-VAC-Receipt").iter().count();
        agent_log("integration_test strict_handler", "request", &format!(r#"{{"method":"{}","path":"{}","receipt_count":{},"request_cid":"{}"}}"#, method_str_early, path_early, receipt_count, correlation_id), "B");
        // #endregion

        let (user_root_key, session_key_pub, api_key, upstream_url, proxy) = {
    let s = state.read().await;
            (s.user_root_public_key, s.session_key.public(), s.api_key.clone(), s.upstream_url.clone(), s.proxy.clone())
        };
        
        let root_biscuit = match verify_root_biscuit(&token_str, &user_root_key, None) {
            Ok(b) => b,
            Err(e) => return e.into_response(),
        };

        // FIX: Manual Authorizer Construction
        let mut authorizer = Authorizer::new();
        if let Err(e) = authorizer.add_token(&root_biscuit) {
            return VacError::InternalError(format!("Failed to add root token: {:?}", e)).into_response();
        }

        // LOAD RECEIPTS FIRST
        for receipt_val in parts.headers.get_all("X-VAC-Receipt") {
            let receipt_str = match receipt_val.to_str() {
                Ok(s) => s,
                Err(_) => return VacError::InvalidTokenFormat.into_response(),
            };
            
            let receipt = match verify_receipt_biscuit(receipt_str, &session_key_pub) {
                Ok(r) => r,
                Err(e) => return e.into_response(),
            };

            let receipt_info = match extract_receipt_info(&receipt) {
                Ok(info) => info,
                Err(e) => {
                    agent_log("integration_test strict_handler", "extract_receipt_info failed", &format!(r#"{{"err":"{:?}"}}"#, e), "B");
                    return e.into_response();
                }
            };
            agent_log("integration_test strict_handler", "receipt_info", &format!(r#"{{"operation":"{}","receipt_cid":"{}","request_cid":"{}"}}"#, receipt_info.operation, receipt_info.correlation_id, correlation_id), "B");

            if let Err(e) = verify_receipt_expiry(receipt_info.timestamp) {
                return e.into_response();
            }
            
            if let Err(e) = verify_correlation_id_match(&receipt_info.correlation_id, &correlation_id) {
                agent_log("integration_test strict_handler", "correlation_id mismatch", &format!(r#"{{"receipt_cid":"{}","request_cid":"{}"}}"#, receipt_info.correlation_id, correlation_id), "B");
                return e.into_response();
            }

            // FIX: Pass receipt_info instead of receipt
            if let Err(e) = add_receipt_facts(&mut authorizer, &receipt_info) {
                return e.into_response();
            }
        }

        // Add Context Facts
        let method_str = parts.method.to_string();
        let path = parts.uri.path().to_string();
        if let Err(e) = add_context_facts(&mut authorizer, &method_str, &path, &correlation_id) {
            return e.into_response();
        }

        // STRICT POLICY
        let policy = r#"
            allow if operation("POST", "/charge"), prior_event($op, $cid, $ts), $op.starts_with("GET /search");
            allow if operation($method, $path), $path != "/charge";
        "#;
        let _ = authorizer.add_code(policy);

        agent_log("integration_test strict_handler", "about to evaluate_policy", &format!(r#"{{"method":"{}","path":"{}"}}"#, method_str, path), "B");
        if let Err(e) = evaluate_policy(&mut authorizer) {
            agent_log("integration_test strict_handler", "policy_denied", &format!(r#"{{"err":"{:?}"}}"#, e), "B");
            return e.into_response();
        }

        // ... Forwarding and Minting logic remains same ...
        let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
            .await
            .unwrap_or_default();
        let response = match proxy.as_ref().forward(&parts, body_bytes, api_key.as_str(), &upstream_url).await {
            Ok(r) => r,
            Err(e) => return e.into_response(),
        };

        if response.status().is_success() {
            let state_read = state.read().await;
            let mut builder = Biscuit::builder();
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

            if let Err(e) = builder.add_fact(Fact::new(
                "prior_event".to_string(),
                vec![
                    biscuit_auth::builder::string(&format!("{} {}", method_str, path)),
                    biscuit_auth::builder::string(&correlation_id),
                    biscuit_auth::builder::int(timestamp as i64),
                ],
            )) {
                return VacError::InternalError(format!("Fact error: {:?}", e)).into_response();
            }

            let receipt_biscuit = match builder.build(&state_read.session_key) {
                Ok(b) => b,
                Err(e) => return VacError::InternalError(format!("Sign error: {:?}", e)).into_response(),
            };
            
            let receipt_b64 = match receipt_biscuit.to_base64() {
                Ok(b) => b,
                Err(e) => return VacError::InternalError(format!("Encode error: {:?}", e)).into_response(),
            };

            let (mut parts, body) = response.into_parts();
            match HeaderValue::from_str(&receipt_b64) {
                Ok(hv) => {
                    parts.headers.insert("X-VAC-Receipt", hv);
                    return axum::response::Response::from_parts(parts, body);
                }
                Err(e) => return VacError::InternalError(format!("Header error: {}", e)).into_response(),
            }
        }

        response
    }
    
    Router::new()
        .route("/*path", any(strict_handler))
        .with_state(state)
}

// -----------------------------------------------------------------------------
// SECTION 4: TEST RUNNER HELPERS (FIXED)
// -----------------------------------------------------------------------------

async fn make_request(
    app: Router, 
    uri: &str, 
    method: Method, 
    auth_header: Option<&str>, 
    receipt_header: Option<&str>
) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
    // Helper that forwards to the main function with no specific ID
    make_request_with_correlation_id(app, uri, method, auth_header, receipt_header, None).await
}

async fn make_request_with_correlation_id(
    app: Router, 
    uri: &str, 
    method: Method, 
    auth_header: Option<&str>, 
    receipt_header: Option<&str>,
    correlation_id: Option<&str>
) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });
    
    let url = format!("http://{}{}", addr, uri);
    let client = reqwest::Client::new();
    let mut request_builder = match method {
        Method::GET => client.get(&url),
        Method::POST => client.post(&url),
        _ => return Err("Unsupported method".into()),
    };
    
    if let Some(auth) = auth_header {
        request_builder = request_builder.header("Authorization", auth);
    }
    
    if let Some(receipt) = receipt_header {
        request_builder = request_builder.header("X-VAC-Receipt", receipt);
    }
    
    if let Some(cid) = correlation_id {
        request_builder = request_builder.header("X-Correlation-ID", cid);
    }
    
    Ok(request_builder.send().await?)
}

// -----------------------------------------------------------------------------
// SECTION 5: INTEGRATION TESTS
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_root_biscuit_verification() {
    let mock_server = MockServer::start().await;
    let root_keypair = KeyPair::new();
    
    Mock::given(method("GET")).and(path("/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server).await;
    
    let state = common::default_test_state(root_keypair.public(), "k", mock_server.uri());
    
    let app = create_permissive_router(state).await;
    let root_biscuit = common::generate_test_root_biscuit(&root_keypair).unwrap();
    let token = root_biscuit.to_base64().unwrap();
    
    let response = make_request(app, "/test", Method::GET, Some(&format!("Bearer {}", token)), None).await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert!(response.headers().contains_key("x-vac-receipt"));
}

#[tokio::test]
async fn test_receipt_minting() {
    let mock_server = MockServer::start().await;
    let root_keypair = KeyPair::new();
    
    Mock::given(method("GET")).and(path("/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server).await;
    
    let state = common::default_test_state(root_keypair.public(), "k", mock_server.uri());
    
    let app = create_permissive_router(state.clone()).await;
    let root_biscuit = common::generate_test_root_biscuit(&root_keypair).unwrap();
    let token = root_biscuit.to_base64().unwrap();
    
    let response = make_request(app, "/test", Method::GET, Some(&format!("Bearer {}", token)), None).await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    
    let receipt_header = response.headers().get("x-vac-receipt").unwrap();
    let receipt_str = receipt_header.to_str().unwrap();
    
    let state_read = state.read().await;
    let pub_key = state_read.session_key.public();
    let receipt = vac_sidecar::verify_receipt_biscuit(receipt_str, &pub_key).unwrap();
    let info = vac_sidecar::extract_receipt_info(&receipt).unwrap();
    assert_eq!(info.operation, "GET /test");
}

#[tokio::test]
async fn test_missing_token() {
    let mock_server = MockServer::start().await;
    let root_keypair = KeyPair::new();
    let state = common::default_test_state(root_keypair.public(), "k", mock_server.uri());
    let app = create_permissive_router(state).await;
    let response = make_request(app, "/test", Method::GET, None, None).await.unwrap();
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn test_invalid_signature() {
    let mock_server = MockServer::start().await;
    let root_keypair = KeyPair::new();
    let state = common::default_test_state(root_keypair.public(), "k", mock_server.uri());
    let app = create_permissive_router(state).await;
    
    let bad_keypair = KeyPair::new();
    let bad_biscuit = common::generate_test_root_biscuit(&bad_keypair).unwrap();
    let token = bad_biscuit.to_base64().unwrap();
    
    let response = make_request(app, "/test", Method::GET, Some(&format!("Bearer {}", token)), None).await.unwrap();
    assert!(response.status().as_u16() == 401 || response.status().as_u16() == 403);
}

// FIX: This test now explicitly manages Correlation ID to avoid mismatch
#[tokio::test]
async fn test_state_gate_enforcement() {
    let mock_server = MockServer::start().await;
    let root_keypair = KeyPair::new();
    
    Mock::given(method("GET")).and(path("/search")).respond_with(ResponseTemplate::new(200)).mount(&mock_server).await;
    Mock::given(method("POST")).and(path("/charge")).respond_with(ResponseTemplate::new(200)).mount(&mock_server).await;
    
    let state = common::default_test_state(root_keypair.public(), "key", mock_server.uri());
    
    let app = create_strict_router(state.clone()).await;
    let root_biscuit = common::generate_test_root_biscuit(&root_keypair).unwrap();
    let token = root_biscuit.to_base64().unwrap();
    
    // FIX: Generate one ID for the whole flow
    let correlation_id = Uuid::new_v4().to_string();
    
    // Case 1: Charge WITHOUT search (Should FAIL)
    let response = make_request_with_correlation_id(
        app.clone(), "/charge", Method::POST, Some(&format!("Bearer {}", token)), None, Some(&correlation_id)
    ).await.unwrap();
    assert_eq!(response.status().as_u16(), 403, "Failed to block charge without receipt");
    
    // Case 2: Search (Should SUCCEED)
    let response = make_request_with_correlation_id(
        app.clone(), "/search", Method::GET, Some(&format!("Bearer {}", token)), None, Some(&correlation_id)
    ).await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    
    let search_receipt = response.headers().get("x-vac-receipt").unwrap().to_str().unwrap();
    
    // Case 3: Charge WITH search receipt (Should SUCCEED)
    let response = make_request_with_correlation_id(
        app, "/charge", Method::POST, Some(&format!("Bearer {}", token)), Some(search_receipt), Some(&correlation_id)
    ).await.unwrap();
    
    if response.status().as_u16() != 200 {
        let body = response.text().await.unwrap();
        panic!("Failed valid charge: {}", body);
    }
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn test_receipt_chain() {
    let mock_server = MockServer::start().await;
    let root_keypair = KeyPair::new();
    
    Mock::given(method("GET")).and(path("/search")).respond_with(ResponseTemplate::new(200).set_body_string("OK")).mount(&mock_server).await;
    Mock::given(method("POST")).and(path("/select")).respond_with(ResponseTemplate::new(200).set_body_string("OK")).mount(&mock_server).await;
    Mock::given(method("POST")).and(path("/charge")).respond_with(ResponseTemplate::new(200).set_body_string("OK")).mount(&mock_server).await;
    
    let state = common::default_test_state(root_keypair.public(), "key", mock_server.uri());
    
    let app = create_permissive_router(state.clone()).await;
    let root_biscuit = common::generate_test_root_biscuit(&root_keypair).unwrap();
    let token = root_biscuit.to_base64().unwrap();
    
    let correlation_id = Uuid::new_v4().to_string();
    
    // Step 1: Search
    let response = make_request_with_correlation_id(
        app.clone(), "/search", Method::GET, Some(&format!("Bearer {}", token)), None, Some(&correlation_id)
    ).await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let search_receipt = response.headers().get("x-vac-receipt").unwrap().to_str().unwrap().to_string();
    
    // Step 2: Select
    let response = make_request_with_correlation_id(
        app.clone(), "/select", Method::POST, Some(&format!("Bearer {}", token)), Some(&search_receipt), Some(&correlation_id)
    ).await.unwrap();
    if response.status().as_u16() != 200 {
        let body = response.text().await.unwrap();
        panic!("Step 2 Failed. Body: {}", body);
    }
    assert_eq!(response.status().as_u16(), 200);
    let select_receipt = response.headers().get("x-vac-receipt").unwrap().to_str().unwrap().to_string();
    
    // Step 3: Charge (Manual request for multi-header support)
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });
    
    let url = format!("http://{}/charge", addr);
    let client = reqwest::Client::new();
    
    let response = client.post(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("X-Correlation-ID", &correlation_id)
        .header("X-VAC-Receipt", search_receipt)
        .header("X-VAC-Receipt", select_receipt)
        .send().await.unwrap();
    
    if response.status().as_u16() != 200 {
        let body = response.text().await.unwrap();
        panic!("Step 3 Failed. Body: {}", body);
    }
    assert_eq!(response.status().as_u16(), 200);
    
    let charge_receipt = response.headers().get("x-vac-receipt").unwrap().to_str().unwrap();
    let state_read = state.read().await;
    let charge_receipt_biscuit = vac_sidecar::verify_receipt_biscuit(charge_receipt, &state_read.session_key.public()).unwrap();
    let charge_info = vac_sidecar::extract_receipt_info(&charge_receipt_biscuit).unwrap();
    assert_eq!(charge_info.operation, "POST /charge");
}