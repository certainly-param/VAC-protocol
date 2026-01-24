pub mod config;
pub mod error;
pub mod state;
pub mod receipt;
pub mod policy;
pub mod proxy;
pub mod biscuit;
pub mod heartbeat;
pub mod revocation;
pub mod adapter;
pub mod delegation;
pub mod security;
pub mod rate_limit;
pub mod replay_cache;

pub use config::{Config, CliArgs};
pub use error::VacError;
pub use state::{SidecarState, SharedState};
pub use receipt::{ReceiptInfo, extract_receipt_info, verify_receipt_expiry, verify_correlation_id_match};
pub use policy::{evaluate_policy, add_context_facts, add_receipt_facts};
pub use policy::extract_adapter_hash;
pub use delegation::{
    DEFAULT_MAX_DELEGATION_DEPTH,
    DELEGATION_HEADER,
    create_delegated_token,
    extract_depth,
    enforce_max_depth,
    verify_delegation_chain,
};
pub use proxy::{Proxy, AxumProxy};
pub use biscuit::{verify_root_biscuit, verify_receipt_biscuit};
pub use heartbeat::start_heartbeat_task;
pub use revocation::{RevocationFilter, extract_token_id};
pub use adapter::{AdapterRegistry, AdapterFact, load_adapter_from_file, load_adapters_from_dir, load_adapter_from_url, extract_facts_from_body};
pub use security::{SecureString, validate_correlation_id, validate_header_name, validate_header_value, validate_body_size, MAX_REQUEST_BODY_SIZE, lock_string_memory};
pub use rate_limit::{RateLimiter, DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW_DURATION};
pub use replay_cache::{ReplayCache, DEFAULT_REPLAY_CACHE_TTL};