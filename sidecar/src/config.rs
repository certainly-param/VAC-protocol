use crate::error::VacError;
use std::env;
use std::path::PathBuf;
use serde::Deserialize;
use clap::Parser;

/// Configuration loaded from CLI args, environment variables, and/or config files
/// 
/// CRITICAL: Sidecar MUST crash if VAC_ROOT_PUBLIC_KEY or VAC_API_KEY is not set
/// 
/// Config precedence: CLI args > env vars > config file > defaults
pub struct Config {
    pub root_public_key: Vec<u8>,
    pub upstream_url: String,
    pub api_key: String,
    pub control_plane_url: String,
    pub heartbeat_interval_secs: u64,
    pub session_key_rotation_interval_secs: u64,
    pub adapters_dir: Option<String>,
    pub log_level: String,
    // Phase 4.7: Rate limiting configuration
    pub rate_limit_max_requests: u32,
    pub rate_limit_window_secs: u64,
    // Phase 4.8: Replay attack mitigation
    pub replay_cache_enabled: bool,
    pub replay_cache_ttl_secs: u64,
}

/// CLI arguments structure for clap
#[derive(Debug, Parser)]
#[command(name = "vac-sidecar")]
#[command(about = "V-A-C Protocol Sidecar - Verifiable Agentic Credential enforcement proxy")]
pub struct CliArgs {
    /// Path to configuration file (TOML or YAML)
    #[arg(long)]
    pub config_file: Option<PathBuf>,
    
    /// Hex-encoded Ed25519 root public key (overrides env/config)
    #[arg(long)]
    pub root_public_key: Option<String>,
    
    /// Upstream API base URL (overrides env/config)
    #[arg(long)]
    pub upstream_url: Option<String>,
    
    /// API key to inject into forwarded requests (overrides env/config)
    #[arg(long)]
    pub api_key: Option<String>,
    
    /// Control Plane URL for heartbeats (overrides env/config)
    #[arg(long)]
    pub control_plane_url: Option<String>,
    
    /// Heartbeat interval in seconds (overrides env/config)
    #[arg(long)]
    pub heartbeat_interval_secs: Option<u64>,
    
    /// Session key rotation interval in seconds (overrides env/config)
    #[arg(long)]
    pub session_key_rotation_interval_secs: Option<u64>,
    
    /// Directory containing WASM adapters (overrides env/config)
    #[arg(long)]
    pub adapters_dir: Option<String>,
    
    /// Logging level: trace, debug, info, warn, error (overrides env/config)
    #[arg(long)]
    pub log_level: Option<String>,
    
    /// Rate limit: Maximum requests per window (overrides env/config)
    #[arg(long)]
    pub rate_limit_max_requests: Option<u32>,
    
    /// Rate limit: Time window in seconds (overrides env/config)
    #[arg(long)]
    pub rate_limit_window_secs: Option<u64>,
    
    /// Replay cache: Enable replay attack mitigation (overrides env/config)
    #[arg(long)]
    pub replay_cache_enabled: Option<bool>,
    
    /// Replay cache: TTL in seconds (overrides env/config)
    #[arg(long)]
    pub replay_cache_ttl_secs: Option<u64>,
}

/// Config file structure (deserialized from TOML/YAML)
#[derive(Debug, Deserialize, Clone)]
struct ConfigFile {
    #[serde(rename = "sidecar")]
    sidecar: Option<SidecarConfig>,
    #[serde(rename = "logging")]
    logging: Option<LoggingConfig>,
    #[serde(rename = "revocation")]
    #[allow(dead_code)] // Placeholder for future bloom filter settings
    revocation: Option<RevocationConfig>,
}

#[derive(Debug, Deserialize, Clone)]
struct SidecarConfig {
    root_public_key: Option<String>,
    upstream_url: Option<String>,
    api_key: Option<String>,
    control_plane_url: Option<String>,
    heartbeat_interval_secs: Option<u64>,
    session_key_rotation_interval_secs: Option<u64>,
    adapters_dir: Option<String>,
    // Phase 4.7: Rate limiting
    rate_limit_max_requests: Option<u32>,
    rate_limit_window_secs: Option<u64>,
    // Phase 4.8: Replay attack mitigation
    replay_cache_enabled: Option<bool>,
    replay_cache_ttl_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
struct LoggingConfig {
    level: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct RevocationConfig {
    // Future: bloom filter settings can go here
    // false_positive_rate: Option<f64>,
    // capacity: Option<usize>,
}

impl Config {
    /// Load configuration with precedence: CLI args > env vars > config file > defaults
    /// 
    /// # Precedence Order
    /// 1. CLI arguments (highest priority)
    /// 2. Environment variables
    /// 3. Config file (TOML or YAML)
    /// 4. Defaults (lowest priority)
    /// 
    /// # Required Fields
    /// - `root_public_key`: Hex-encoded Ed25519 public key (MUST be set via CLI, env, or config file)
    /// - `api_key`: API key to inject into forwarded requests (MUST be set via CLI, env, or config file)
    /// 
    /// # Notes
    /// - Hex encoding chosen over Base64 because:
    ///   - Base64 contains +, /, = which break in shell/env/kubernetes
    ///   - Hex (a1b2...) is always safe for all environments
    pub fn load(cli_args: &CliArgs) -> Result<Config, VacError> {
        // Load .env file if present (but don't override existing env vars)
        // Note: dotenv::dotenv() by default doesn't override existing env vars,
        // so test-set env vars will take precedence over .env file values.
        dotenv::dotenv().ok();
        
        // Step 1: Load config file (if specified)
        let file_config = if let Some(config_path) = &cli_args.config_file {
            Self::load_from_file(config_path)?
        } else {
            None
        };
        
        // Step 2: Load environment variables (reads current env vars, which may include
        // values set by tests or from .env file, but test-set vars take precedence)
        let env_config = Self::load_from_env()?;
        
        // Step 3: Apply precedence (CLI > env > file > defaults)
        let root_public_key_str = cli_args.root_public_key
            .as_ref()
            .or_else(|| env_config.root_public_key.as_ref())
            .or_else(|| file_config.as_ref().and_then(|f| f.sidecar.as_ref()?.root_public_key.as_ref()))
            .ok_or_else(|| VacError::ConfigError(
                "root_public_key must be set via --root-public-key, VAC_ROOT_PUBLIC_KEY env var, or config file".to_string()
            ))?;
        
        let root_public_key = hex::decode(root_public_key_str)
            .map_err(|_| VacError::ConfigError(
                "root_public_key must be valid hex-encoded Ed25519 public key (64 hex characters)".to_string()
            ))?;
        
        // Validate key length (Ed25519 public keys are 32 bytes = 64 hex chars)
        if root_public_key.len() != 32 {
            return Err(VacError::ConfigError(
                format!("root_public_key must be 32 bytes (64 hex characters), got {} bytes", root_public_key.len())
            ));
        }
        
        let upstream_url = cli_args.upstream_url
            .as_ref()
            .or_else(|| env_config.upstream_url.as_ref())
            .or_else(|| file_config.as_ref().and_then(|f| f.sidecar.as_ref()?.upstream_url.as_ref()))
            .unwrap_or(&"http://localhost:8080".to_string())
            .clone();
        
        // Precedence: CLI > env > file > defaults
        let api_key = cli_args.api_key
            .as_ref()
            .or_else(|| {
                // Debug: verify env var is being read
                env_config.api_key.as_ref()
            })
            .or_else(|| file_config.as_ref().and_then(|f| f.sidecar.as_ref()?.api_key.as_ref()))
            .ok_or_else(|| VacError::ConfigError(
                "api_key must be set via --api-key, VAC_API_KEY env var, or config file".to_string()
            ))?
            .clone();
        
        let control_plane_url = cli_args.control_plane_url
            .as_ref()
            .or_else(|| env_config.control_plane_url.as_ref())
            .or_else(|| file_config.as_ref().and_then(|f| f.sidecar.as_ref()?.control_plane_url.as_ref()))
            .unwrap_or(&"http://localhost:8081".to_string())
            .clone();
        
        let heartbeat_interval_secs = cli_args.heartbeat_interval_secs
            .or(env_config.heartbeat_interval_secs)
            .or_else(|| file_config.as_ref().and_then(|f| f.sidecar.as_ref()?.heartbeat_interval_secs))
            .unwrap_or(60);
        
        let session_key_rotation_interval_secs = cli_args.session_key_rotation_interval_secs
            .or(env_config.session_key_rotation_interval_secs)
            .or_else(|| file_config.as_ref().and_then(|f| f.sidecar.as_ref()?.session_key_rotation_interval_secs))
            .unwrap_or(300);
        
        let adapters_dir = cli_args.adapters_dir
            .as_ref()
            .or_else(|| env_config.adapters_dir.as_ref())
            .or_else(|| file_config.as_ref().and_then(|f| f.sidecar.as_ref()?.adapters_dir.as_ref()))
            .cloned();
        
        let log_level = cli_args.log_level
            .as_ref()
            .or_else(|| env_config.log_level.as_ref())
            .or_else(|| file_config.as_ref().and_then(|f| f.logging.as_ref()?.level.as_ref()))
            .unwrap_or(&"info".to_string())
            .clone();
        
        // Phase 4.7: Rate limiting configuration
        use crate::rate_limit::{DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW_DURATION};
        let rate_limit_max_requests = cli_args.rate_limit_max_requests
            .or(env_config.rate_limit_max_requests)
            .or_else(|| file_config.as_ref().and_then(|f| f.sidecar.as_ref()?.rate_limit_max_requests))
            .unwrap_or(DEFAULT_MAX_REQUESTS);
        
        let rate_limit_window_secs = cli_args.rate_limit_window_secs
            .or(env_config.rate_limit_window_secs)
            .or_else(|| file_config.as_ref().and_then(|f| f.sidecar.as_ref()?.rate_limit_window_secs))
            .unwrap_or(DEFAULT_WINDOW_DURATION.as_secs());
        
        // Phase 4.8: Replay attack mitigation configuration
        use crate::replay_cache::DEFAULT_REPLAY_CACHE_TTL;
        let replay_cache_enabled = cli_args.replay_cache_enabled
            .or(env_config.replay_cache_enabled)
            .or_else(|| file_config.as_ref().and_then(|f| f.sidecar.as_ref()?.replay_cache_enabled))
            .unwrap_or(false); // Default: disabled (rely on upstream API idempotency)
        
        let replay_cache_ttl_secs = cli_args.replay_cache_ttl_secs
            .or(env_config.replay_cache_ttl_secs)
            .or_else(|| file_config.as_ref().and_then(|f| f.sidecar.as_ref()?.replay_cache_ttl_secs))
            .unwrap_or(DEFAULT_REPLAY_CACHE_TTL.as_secs());
        
        Ok(Config {
            root_public_key,
            upstream_url,
            api_key,
            control_plane_url,
            heartbeat_interval_secs,
            session_key_rotation_interval_secs,
            adapters_dir,
            log_level,
            rate_limit_max_requests,
            rate_limit_window_secs,
            replay_cache_enabled,
            replay_cache_ttl_secs,
        })
    }
    
    /// Load configuration from file (TOML or YAML)
    fn load_from_file(path: &PathBuf) -> Result<Option<ConfigFile>, VacError> {
        use config::Config as ConfigBuilder;
        
        // Check if file exists first
        if !path.exists() {
            return Err(VacError::ConfigError(
                format!("Config file not found: {}", path.display())
            ));
        }
        
        // Determine file format from extension
        let file_source = match path.extension().and_then(|s| s.to_str()) {
            Some("toml") => config::File::from(path.as_path()).format(config::FileFormat::Toml),
            Some("yaml") | Some("yml") => config::File::from(path.as_path()).format(config::FileFormat::Yaml),
            _ => {
                // Try to auto-detect: default to TOML if extension unknown
                config::File::from(path.as_path()).format(config::FileFormat::Toml)
            }
        };
        
        let builder = ConfigBuilder::builder()
            .add_source(file_source)
            .build()
            .map_err(|e| VacError::ConfigError(format!("Failed to load config file: {}", e)))?;
        
        let config_file: ConfigFile = builder
            .try_deserialize()
            .map_err(|e| VacError::ConfigError(format!("Failed to parse config file: {}", e)))?;
        
        Ok(Some(config_file))
    }
    
    /// Load configuration from environment variables only (for fallback/defaults)
    /// 
    /// Note: This reads env vars AFTER dotenv has been called, so any .env file
    /// values will have been loaded, but explicit env vars (set by tests or shell)
    /// take precedence since dotenv doesn't override existing vars.
    fn load_from_env() -> Result<EnvConfig, VacError> {
        // Read env vars directly - these will include:
        // 1. Values set explicitly (e.g., by tests or shell)
        // 2. Values from .env file (if dotenv was called and var wasn't already set)
        let root_public_key = env::var("VAC_ROOT_PUBLIC_KEY").ok();
        let upstream_url = env::var("VAC_UPSTREAM_URL").ok();
        let api_key = env::var("VAC_API_KEY").ok();
        let control_plane_url = env::var("VAC_CONTROL_PLANE_URL").ok();
        let heartbeat_interval_secs = env::var("VAC_HEARTBEAT_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok());
        let session_key_rotation_interval_secs = env::var("VAC_SESSION_KEY_ROTATION_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok());
        let adapters_dir = env::var("VAC_ADAPTERS_DIR").ok();
        let log_level = env::var("VAC_LOG_LEVEL").ok();
        // Phase 4.7: Rate limiting env vars
        let rate_limit_max_requests = env::var("VAC_RATE_LIMIT_MAX_REQUESTS")
            .ok()
            .and_then(|v| v.parse::<u32>().ok());
        let rate_limit_window_secs = env::var("VAC_RATE_LIMIT_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok());
        // Phase 4.8: Replay cache env vars
        let replay_cache_enabled = env::var("VAC_REPLAY_CACHE_ENABLED")
            .ok()
            .and_then(|v| v.parse::<bool>().ok());
        let replay_cache_ttl_secs = env::var("VAC_REPLAY_CACHE_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok());
        
        Ok(EnvConfig {
            root_public_key,
            upstream_url,
            api_key,
            control_plane_url,
            heartbeat_interval_secs,
            session_key_rotation_interval_secs,
            adapters_dir,
            log_level,
            rate_limit_max_requests,
            rate_limit_window_secs,
            replay_cache_enabled,
            replay_cache_ttl_secs,
        })
    }
}

/// Intermediate structure for env var config (all optional for precedence)
struct EnvConfig {
    root_public_key: Option<String>,
    upstream_url: Option<String>,
    api_key: Option<String>,
    control_plane_url: Option<String>,
    heartbeat_interval_secs: Option<u64>,
    session_key_rotation_interval_secs: Option<u64>,
    adapters_dir: Option<String>,
    log_level: Option<String>,
    // Phase 4.7: Rate limiting
    rate_limit_max_requests: Option<u32>,
    rate_limit_window_secs: Option<u64>,
    // Phase 4.8: Replay attack mitigation
    replay_cache_enabled: Option<bool>,
    replay_cache_ttl_secs: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_config_precedence_cli_overrides_env() {
        // Clean up any existing env vars first
        std::env::remove_var("VAC_ROOT_PUBLIC_KEY");
        std::env::remove_var("VAC_API_KEY");
        
        // Set env var
        std::env::set_var("VAC_ROOT_PUBLIC_KEY", "0000000000000000000000000000000000000000000000000000000000000000");
        std::env::set_var("VAC_API_KEY", "env-api-key");
        
        // CLI args override env
        let cli_args = CliArgs {
            config_file: None,
            root_public_key: Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string()),
            upstream_url: None,
            api_key: Some("cli-api-key".to_string()),
            control_plane_url: None,
            heartbeat_interval_secs: None,
            session_key_rotation_interval_secs: None,
            adapters_dir: None,
            log_level: None,
            rate_limit_max_requests: None,
            rate_limit_window_secs: None,
            replay_cache_enabled: None,
            replay_cache_ttl_secs: None,
        };
        
        let config = Config::load(&cli_args).unwrap();
        assert_eq!(config.api_key, "cli-api-key");
        
        // Cleanup
        std::env::remove_var("VAC_ROOT_PUBLIC_KEY");
        std::env::remove_var("VAC_API_KEY");
    }

    #[test]
    fn test_config_load_from_file() {
        // Create temp dir and config file
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.toml");
        
        let toml_content = r#"
[sidecar]
root_public_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
api_key = "file-api-key"
upstream_url = "http://file-upstream:8080"
heartbeat_interval_secs = 120

[logging]
level = "warn"
"#;
        
        fs::write(&config_path, toml_content).unwrap();
        
        let cli_args = CliArgs {
            config_file: Some(config_path),
            root_public_key: None,
            upstream_url: None,
            api_key: None,
            control_plane_url: None,
            heartbeat_interval_secs: None,
            session_key_rotation_interval_secs: None,
            adapters_dir: None,
            log_level: None,
            rate_limit_max_requests: None,
            rate_limit_window_secs: None,
            replay_cache_enabled: None,
            replay_cache_ttl_secs: None,
        };
        
        let config = Config::load(&cli_args).unwrap();
        assert_eq!(config.api_key, "file-api-key");
        assert_eq!(config.upstream_url, "http://file-upstream:8080");
        assert_eq!(config.heartbeat_interval_secs, 120);
        assert_eq!(config.log_level, "warn");
    }

    #[test]
    fn test_config_env_overrides_file() {
        // Clean up any existing env vars first (including from .env file)
        std::env::remove_var("VAC_ROOT_PUBLIC_KEY");
        std::env::remove_var("VAC_API_KEY");
        
        // Set env var (must be set before Config::load is called)
        // This should take precedence over .env file and config file
        std::env::set_var("VAC_ROOT_PUBLIC_KEY", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        std::env::set_var("VAC_API_KEY", "env-api-key");
        
        // Verify env var is set (debug check)
        assert_eq!(std::env::var("VAC_API_KEY").unwrap(), "env-api-key");
        
        // Create config file with different value
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.toml");
        
        let toml_content = r#"
[sidecar]
root_public_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
api_key = "file-api-key"
"#;
        
        fs::write(&config_path, toml_content).unwrap();
        
        let cli_args = CliArgs {
            config_file: Some(config_path),
            root_public_key: None,
            upstream_url: None,
            api_key: None,
            control_plane_url: None,
            heartbeat_interval_secs: None,
            session_key_rotation_interval_secs: None,
            adapters_dir: None,
            log_level: None,
            rate_limit_max_requests: None,
            rate_limit_window_secs: None,
            replay_cache_enabled: None,
            replay_cache_ttl_secs: None,
        };
        
        // Verify env var is still set right before loading
        match std::env::var("VAC_API_KEY") {
            Ok(val) => assert_eq!(val, "env-api-key", "Env var must be set before Config::load"),
            Err(e) => panic!("VAC_API_KEY env var not found: {:?}. This suggests test isolation issues.", e),
        }
        
        let config = Config::load(&cli_args).unwrap();
        // Env should override file (precedence: CLI > env > file > defaults)
        assert_eq!(config.api_key, "env-api-key", "Env var should override config file value. Got: {}", config.api_key);
        
        // Cleanup
        std::env::remove_var("VAC_ROOT_PUBLIC_KEY");
        std::env::remove_var("VAC_API_KEY");
    }

    #[test]
    fn test_config_defaults() {
        // Clean up any existing env vars first
        std::env::remove_var("VAC_ROOT_PUBLIC_KEY");
        std::env::remove_var("VAC_API_KEY");
        
        std::env::set_var("VAC_ROOT_PUBLIC_KEY", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        std::env::set_var("VAC_API_KEY", "test-api-key");
        
        // Verify env vars are set
        assert!(std::env::var("VAC_API_KEY").is_ok(), "VAC_API_KEY must be set");
        assert!(std::env::var("VAC_ROOT_PUBLIC_KEY").is_ok(), "VAC_ROOT_PUBLIC_KEY must be set");
        
        let cli_args = CliArgs {
            config_file: None,
            root_public_key: None,
            upstream_url: None,
            api_key: None,
            control_plane_url: None,
            heartbeat_interval_secs: None,
            session_key_rotation_interval_secs: None,
            adapters_dir: None,
            log_level: None,
            rate_limit_max_requests: None,
            rate_limit_window_secs: None,
            replay_cache_enabled: None,
            replay_cache_ttl_secs: None,
        };
        
        let config = Config::load(&cli_args).unwrap();
        // Should use defaults
        assert_eq!(config.upstream_url, "http://localhost:8080");
        assert_eq!(config.control_plane_url, "http://localhost:8081");
        assert_eq!(config.heartbeat_interval_secs, 60);
        assert_eq!(config.session_key_rotation_interval_secs, 300);
        assert_eq!(config.log_level, "info");
        
        // Cleanup
        std::env::remove_var("VAC_ROOT_PUBLIC_KEY");
        std::env::remove_var("VAC_API_KEY");
    }
}

// Config integration tests are in integration_test.rs
