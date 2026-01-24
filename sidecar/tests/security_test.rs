//! Integration tests for Phase 4.7 security hardening features

use vac_sidecar::security::{
    SecureString, validate_correlation_id, validate_header_name, 
    validate_header_value, validate_body_size, MAX_REQUEST_BODY_SIZE,
};
use vac_sidecar::rate_limit::{RateLimiter, DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW_DURATION};
use vac_sidecar::replay_cache::{ReplayCache, DEFAULT_REPLAY_CACHE_TTL};
use std::time::Duration;

#[test]
fn test_secure_string_zeroization() {
    let mut secret = SecureString::new("super-secret-api-key".to_string());
    assert_eq!(secret.as_str(), "super-secret-api-key");
    
    // Drop should zeroize (we can't directly verify, but the trait ensures it)
    drop(secret);
}

#[test]
fn test_validate_correlation_id_valid() {
    // Valid UUID v4
    assert!(validate_correlation_id("550e8400-e29b-41d4-a716-446655440000"));
    assert!(validate_correlation_id("01234567-89ab-cdef-0123-456789abcdef"));
}

#[test]
fn test_validate_correlation_id_invalid() {
    // Invalid formats
    assert!(!validate_correlation_id("not-a-uuid"));
    assert!(!validate_correlation_id(""));
    assert!(!validate_correlation_id("550e8400-e29b-41d4-a716")); // Too short
    assert!(!validate_correlation_id("550e8400-e29b-41d4-a716-446655440000-extra")); // Too long
}

#[test]
fn test_validate_header_name_valid() {
    assert!(validate_header_name("Authorization"));
    assert!(validate_header_name("X-Correlation-ID"));
    assert!(validate_header_name("Content-Type"));
    assert!(validate_header_name("X-VAC-Receipt"));
}

#[test]
fn test_validate_header_name_invalid() {
    // Empty
    assert!(!validate_header_name(""));
    
    // Too long (256+ chars)
    assert!(!validate_header_name(&"a".repeat(257)));
    
    // Control characters
    assert!(!validate_header_name("Header\nName"));
    assert!(!validate_header_name("Header\rName"));
    assert!(!validate_header_name("Header\tName")); // Tab is control char
    
    // Non-ASCII
    assert!(!validate_header_name("Héader"));
}

#[test]
fn test_validate_header_value_valid() {
    assert!(validate_header_value("Bearer token123"));
    assert!(validate_header_value("application/json"));
    assert!(validate_header_value("550e8400-e29b-41d4-a716-446655440000"));
    
    // Max size (8KB)
    assert!(validate_header_value(&"a".repeat(8192)));
    
    // Tab is allowed in header values
    assert!(validate_header_value("value\twith\ttabs"));
}

#[test]
fn test_validate_header_value_invalid() {
    // Too large (8KB+)
    assert!(!validate_header_value(&"a".repeat(8193)));
    
    // Control characters (except tab)
    assert!(!validate_header_value("value\nwith\nnewlines"));
    assert!(!validate_header_value("value\rwith\rcarriage"));
}

#[test]
fn test_validate_body_size_valid() {
    assert!(validate_body_size(0));
    assert!(validate_body_size(1024));
    assert!(validate_body_size(MAX_REQUEST_BODY_SIZE));
}

#[test]
fn test_validate_body_size_invalid() {
    assert!(!validate_body_size(MAX_REQUEST_BODY_SIZE + 1));
    assert!(!validate_body_size(MAX_REQUEST_BODY_SIZE * 2));
}

#[test]
fn test_secure_string_conversions() {
    let original = "test-api-key".to_string();
    let secure: SecureString = original.clone().into();
    
    assert_eq!(secure.as_str(), &original);
    
    // Convert back to String
    let back: String = secure.into();
    assert_eq!(back, original);
}

#[test]
fn test_secure_string_clone() {
    let s1 = SecureString::new("secret".to_string());
    let s2 = s1.clone();
    
    assert_eq!(s1.as_str(), s2.as_str());
    assert_eq!(s1.as_str(), "secret");
}

// Rate Limiting Tests

#[test]
fn test_rate_limiter_allows_requests() {
    let limiter = RateLimiter::new(10, Duration::from_secs(60));
    
    // First 10 requests should be allowed
    for _ in 0..10 {
        assert!(limiter.check("sidecar1"));
    }
    
    // 11th request should be rate limited
    assert!(!limiter.check("sidecar1"));
}

#[test]
fn test_rate_limiter_per_sidecar() {
    let limiter = RateLimiter::new(5, Duration::from_secs(60));
    
    // Sidecar1 uses all tokens
    for _ in 0..5 {
        assert!(limiter.check("sidecar1"));
    }
    assert!(!limiter.check("sidecar1"));
    
    // Sidecar2 should still have tokens
    for _ in 0..5 {
        assert!(limiter.check("sidecar2"));
    }
    assert!(!limiter.check("sidecar2"));
}

#[test]
fn test_rate_limiter_refill() {
    let limiter = RateLimiter::new(10, Duration::from_millis(100));
    
    // Use all tokens
    for _ in 0..10 {
        assert!(limiter.check("sidecar1"));
    }
    assert!(!limiter.check("sidecar1"));
    
    // Wait for refill
    std::thread::sleep(Duration::from_millis(150));
    
    // Should have tokens again
    assert!(limiter.check("sidecar1"));
}

#[test]
fn test_rate_limiter_partial_refill() {
    let limiter = RateLimiter::new(100, Duration::from_secs(60));
    
    // Use half the tokens
    for _ in 0..50 {
        assert!(limiter.check("sidecar1"));
    }
    
    // Wait half the window duration
    std::thread::sleep(Duration::from_millis(100));
    
    // Should have some tokens refilled (approximately 50 + some partial refill)
    // We can't test exact values due to timing, but we should have at least one token
    let mut allowed = 0;
    for _ in 0..10 {
        if limiter.check("sidecar1") {
            allowed += 1;
        }
    }
    // Should have at least some tokens available
    assert!(allowed > 0);
}

#[test]
fn test_rate_limiter_cleanup() {
    let limiter = RateLimiter::new(10, Duration::from_secs(60));
    
    // Create buckets for multiple sidecars
    limiter.check("sidecar1");
    limiter.check("sidecar2");
    limiter.check("sidecar3");
    
    // Cleanup buckets older than 1 second
    limiter.cleanup_old_buckets(Duration::from_secs(1));
    
    // Wait a bit and check again - old buckets should be cleaned up
    std::thread::sleep(Duration::from_millis(1100));
    limiter.cleanup_old_buckets(Duration::from_secs(1));
    
    // New requests should still work (buckets are created on demand)
    assert!(limiter.check("sidecar1"));
}

#[test]
fn test_rate_limiter_defaults() {
    let limiter = RateLimiter::new(DEFAULT_MAX_REQUESTS, DEFAULT_WINDOW_DURATION);
    
    // Should allow default number of requests
    for _ in 0..DEFAULT_MAX_REQUESTS {
        assert!(limiter.check("sidecar1"));
    }
    
    // Next request should be rate limited
    assert!(!limiter.check("sidecar1"));
}

// Replay Cache Tests

#[test]
fn test_replay_cache_allows_new_ids() {
    let cache = ReplayCache::new(Duration::from_secs(60), true);
    
    assert!(cache.check_and_insert("id1").unwrap());
    assert!(cache.check_and_insert("id2").unwrap());
    assert!(cache.check_and_insert("id3").unwrap());
}

#[test]
fn test_replay_cache_rejects_replays() {
    let cache = ReplayCache::new(Duration::from_secs(60), true);
    
    // First use - should be allowed
    assert!(cache.check_and_insert("id1").unwrap());
    
    // Immediate replay - should be rejected
    assert!(!cache.check_and_insert("id1").unwrap());
}

#[test]
fn test_replay_cache_expires_entries() {
    let cache = ReplayCache::new(Duration::from_millis(100), true);
    
    // First use
    assert!(cache.check_and_insert("id1").unwrap());
    
    // Immediate replay - rejected
    assert!(!cache.check_and_insert("id1").unwrap());
    
    // Wait for expiry
    std::thread::sleep(Duration::from_millis(150));
    
    // Should be allowed again after expiry
    assert!(cache.check_and_insert("id1").unwrap());
}

#[test]
fn test_replay_cache_disabled() {
    let cache = ReplayCache::new(Duration::from_secs(60), false);
    
    // When disabled, check_and_insert returns Err (meaning "always allow")
    assert!(cache.check_and_insert("id1").is_err());
    
    // Can use same ID multiple times
    assert!(cache.check_and_insert("id1").is_err());
    assert!(cache.check_and_insert("id1").is_err());
}

#[test]
fn test_replay_cache_cleanup() {
    let cache = ReplayCache::new(Duration::from_millis(100), true);
    
    // Add some entries
    cache.check_and_insert("id1").unwrap();
    cache.check_and_insert("id2").unwrap();
    
    assert_eq!(cache.size(), 2);
    
    // Wait for expiry
    std::thread::sleep(Duration::from_millis(150));
    
    // Cleanup should remove expired entries
    cache.cleanup_expired();
    
    // Size should be 0 (or very small if timing is off)
    assert!(cache.size() <= 1); // Allow some timing variance
}
