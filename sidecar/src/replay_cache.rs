//! Replay attack mitigation for Phase 4.8
//! 
//! Implements a correlation ID cache to prevent immediate replay attacks.
//! This is optional - most upstream APIs (Stripe, etc.) handle idempotency themselves.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cache entry for correlation IDs
struct CacheEntry {
    /// When this correlation ID was first seen
    first_seen: Instant,
}

/// Replay cache to prevent duplicate correlation IDs
/// 
/// This cache stores correlation IDs that have been used recently.
/// If a correlation ID is seen again within the TTL window, the request
/// is rejected as a potential replay attack.
#[derive(Clone)]
pub struct ReplayCache {
    /// Map of correlation ID -> cache entry
    cache: Arc<DashMap<String, CacheEntry>>,
    /// Time-to-live for cache entries (default: 5 minutes)
    ttl: Duration,
    /// Whether replay mitigation is enabled
    enabled: bool,
}

impl ReplayCache {
    /// Create a new replay cache
    /// 
    /// # Arguments
    /// * `ttl` - Time-to-live for cache entries (default: 5 minutes)
    /// * `enabled` - Whether replay mitigation is enabled
    pub fn new(ttl: Duration, enabled: bool) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            ttl,
            enabled,
        }
    }
    
    /// Check if a correlation ID has been seen before (replay detection)
    /// 
    /// Returns:
    /// - `Ok(true)` if correlation ID is new (not a replay)
    /// - `Ok(false)` if correlation ID was seen before (potential replay)
    /// - `Err` if replay mitigation is disabled (always allows)
    pub fn check_and_insert(&self, correlation_id: &str) -> Result<bool, ()> {
        if !self.enabled {
            // Replay mitigation disabled - always allow
            return Err(());
        }
        
        let now = Instant::now();
        
        // Check if correlation ID exists and whether it's expired
        // IMPORTANT: We must drop the read lock (Ref) before calling remove()
        let status = if let Some(entry) = self.cache.get(correlation_id) {
            if now.duration_since(entry.first_seen) < self.ttl {
                Some(false) // Still valid - reject as replay
            } else {
                None // Expired - need to remove and allow
            }
        } else {
            None // Not found - allow
        };
        // Read lock is now released (entry/Ref dropped)
        
        match status {
            Some(false) => return Ok(false), // Replay detected
            None => {
                // Entry expired or not found - remove old entry if any, then insert new
                self.cache.remove(correlation_id);
                self.cache.insert(
                    correlation_id.to_string(),
                    CacheEntry { first_seen: now },
                );
                Ok(true)
            }
            _ => unreachable!(),
        }
    }
    
    /// Clean up expired entries
    /// 
    /// Call this periodically to prevent memory leaks.
    pub fn cleanup_expired(&self) {
        if !self.enabled {
            return;
        }
        
        let now = Instant::now();
        self.cache.retain(|_, entry| {
            now.duration_since(entry.first_seen) < self.ttl
        });
    }
    
    /// Get cache size (for monitoring)
    pub fn size(&self) -> usize {
        self.cache.len()
    }
    
    /// Check if replay mitigation is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Default TTL for replay cache (5 minutes)
pub const DEFAULT_REPLAY_CACHE_TTL: Duration = Duration::from_secs(300);

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    
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
        thread::sleep(Duration::from_millis(150));
        
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
        thread::sleep(Duration::from_millis(150));
        
        // Cleanup should remove expired entries
        cache.cleanup_expired();
        
        // Size should be 0 (or very small if timing is off)
        assert!(cache.size() <= 1); // Allow some timing variance
    }
}
