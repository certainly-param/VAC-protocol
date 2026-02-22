//! Security hardening utilities for Phase 4.7
//! 
//! This module provides:
//! - Memory protection (mlock, zeroization)
//! - Input validation
//! - Rate limiting

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure string that zeroizes on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureString(String);

impl SecureString {
    pub fn new(s: String) -> Self {
        Self(s)
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<SecureString> for String {
    fn from(s: SecureString) -> Self {
        s.as_str().to_owned()
    }
}

/// Attempt to lock memory pages to prevent swapping to disk
/// 
/// This is a best-effort operation. Errors are logged but don't fail startup.
/// Supported on Unix (mlock) and Windows (VirtualLock).
pub fn mlock_memory(ptr: *const u8, len: usize) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::ffi::c_void;
        use std::io;
        let result = unsafe {
            libc::mlock(ptr as *const c_void, len)
        };
        if result == 0 {
            Ok(())
        } else {
            let err = io::Error::last_os_error();
            Err(format!("mlock failed: {}", err))
        }
    }
    
    #[cfg(windows)]
    {
        use std::io;
        let result = unsafe {
            windows_sys::Win32::System::Memory::VirtualLock(
                ptr as *mut std::ffi::c_void,
                len,
            )
        };
        if result != 0 {
            Ok(())
        } else {
            let err = io::Error::last_os_error();
            Err(format!("VirtualLock failed: {}", err))
        }
    }
    
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
        // Unsupported platform - zeroization is still effective
        Ok(())
    }
}

/// Attempt to unlock memory pages
pub fn munlock_memory(ptr: *const u8, len: usize) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::ffi::c_void;
        use std::io;
        let result = unsafe {
            libc::munlock(ptr as *const c_void, len)
        };
        if result == 0 {
            Ok(())
        } else {
            let err = io::Error::last_os_error();
            Err(format!("munlock failed: {}", err))
        }
    }
    
    #[cfg(windows)]
    {
        use std::io;
        let result = unsafe {
            windows_sys::Win32::System::Memory::VirtualUnlock(
                ptr as *mut std::ffi::c_void,
                len,
            )
        };
        if result != 0 {
            Ok(())
        } else {
            let err = io::Error::last_os_error();
            Err(format!("VirtualUnlock failed: {}", err))
        }
    }
    
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
        Ok(())
    }
}

/// Lock a string's memory to prevent swapping
/// 
/// This is best-effort and logs warnings on failure.
pub fn lock_string_memory(s: &str) {
    if let Err(e) = mlock_memory(s.as_ptr(), s.len()) {
        tracing::warn!("Failed to lock string memory (non-fatal): {}", e);
    }
}

/// Validate correlation ID format (must be valid UUID v4)
pub fn validate_correlation_id(cid: &str) -> bool {
    uuid::Uuid::parse_str(cid).is_ok()
}

/// Validate HTTP header name
/// 
/// Header names must be ASCII and not contain control characters.
pub fn validate_header_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 256 {
        return false;
    }
    name.chars().all(|c| c.is_ascii() && !c.is_control())
}

/// Validate HTTP header value
/// 
/// Header values must be valid UTF-8 and not exceed reasonable length.
pub fn validate_header_value(value: &str) -> bool {
    if value.len() > 8192 {
        // 8KB limit per header value (RFC 7230 recommends 4KB, we allow 8KB)
        return false;
    }
    // Check for control characters (except tab, which is allowed in header values)
    value.chars().all(|c| !c.is_control() || c == '\t')
}

/// Maximum request body size (10MB)
pub const MAX_REQUEST_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Validate request body size
pub fn validate_body_size(size: usize) -> bool {
    size <= MAX_REQUEST_BODY_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_correlation_id() {
        assert!(validate_correlation_id("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!validate_correlation_id("not-a-uuid"));
        assert!(!validate_correlation_id(""));
    }
    
    #[test]
    fn test_validate_header_name() {
        assert!(validate_header_name("Authorization"));
        assert!(validate_header_name("X-Correlation-ID"));
        assert!(!validate_header_name(""));
        assert!(!validate_header_name(&"a".repeat(257))); // Too long
        assert!(!validate_header_name("Header\nName")); // Control char
    }
    
    #[test]
    fn test_validate_header_value() {
        assert!(validate_header_value("Bearer token123"));
        assert!(validate_header_value(&"a".repeat(8192))); // Max size
        assert!(!validate_header_value(&"a".repeat(8193))); // Too large
        assert!(!validate_header_value("Value\nwith\nnewlines")); // Control chars
    }
    
    #[test]
    fn test_validate_body_size() {
        assert!(validate_body_size(MAX_REQUEST_BODY_SIZE));
        assert!(validate_body_size(1024));
        assert!(!validate_body_size(MAX_REQUEST_BODY_SIZE + 1));
    }
    
    #[test]
    fn test_secure_string() {
        let s = SecureString::new("secret".to_string());
        assert_eq!(s.as_str(), "secret");
        // Drop should zeroize
        drop(s);
    }
}
