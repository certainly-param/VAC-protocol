//! Rate limiting for Phase 4.7 security hardening
//! 
//! Implements a simple token bucket rate limiter to prevent DoS attacks.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::HashMap;

/// Token bucket rate limiter
/// 
/// Allows a certain number of requests per time window.
/// Uses a sliding window approach with token bucket algorithm.
#[derive(Clone)]
pub struct RateLimiter {
    /// Maximum requests per window
    max_requests: u32,
    /// Time window duration
    window_duration: Duration,
    /// Per-sidecar state (sidecar_id -> bucket state)
    buckets: Arc<Mutex<HashMap<String, BucketState>>>,
}

struct BucketState {
    /// Number of tokens available
    tokens: u32,
    /// Last refill time
    last_refill: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter
    /// 
    /// # Arguments
    /// * `max_requests` - Maximum number of requests allowed per window
    /// * `window_duration` - Time window duration (e.g., Duration::from_secs(60) for 60 seconds)
    pub fn new(max_requests: u32, window_duration: Duration) -> Self {
        Self {
            max_requests,
            window_duration,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Check if a request should be allowed
    /// 
    /// Returns `true` if the request should be allowed, `false` if rate limited.
    pub fn check(&self, sidecar_id: &str) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        
        // Get or create bucket state for this sidecar
        let bucket = buckets.entry(sidecar_id.to_string()).or_insert_with(|| {
            BucketState {
                tokens: self.max_requests,
                last_refill: Instant::now(),
            }
        });
        
        // Refill tokens based on elapsed time
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill);
        
        if elapsed >= self.window_duration {
            // Full refill if window has passed
            bucket.tokens = self.max_requests;
            bucket.last_refill = now;
        } else {
            // Partial refill based on elapsed time
            let tokens_to_add = (elapsed.as_secs_f64() / self.window_duration.as_secs_f64()) 
                * self.max_requests as f64;
            // Only advance last_refill when at least 1 whole token is earned,
            // preventing sub-token drift from compounding on every check.
            if tokens_to_add >= 1.0 {
                bucket.tokens = (bucket.tokens as f64 + tokens_to_add)
                    .min(self.max_requests as f64) as u32;
                bucket.last_refill = now;
            }
        }
        
        // Check if we have tokens available
        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            true
        } else {
            false
        }
    }
    
    /// Clean up old bucket states (call periodically to prevent memory leak)
    pub fn cleanup_old_buckets(&self, max_age: Duration) {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();
        
        buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_refill) < max_age
        });
    }
}

/// Default rate limit: 100 requests per minute
pub const DEFAULT_MAX_REQUESTS: u32 = 100;
pub const DEFAULT_WINDOW_DURATION: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    
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
        thread::sleep(Duration::from_millis(150));
        
        // Should have tokens again
        assert!(limiter.check("sidecar1"));
    }
}
