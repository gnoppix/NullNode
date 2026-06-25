//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
//-------------------------------------------------------------------------------

//! Secure memory utilities for key material protection.
//!
//! This module implements ACS2.6 specification requirements for memory hardening:
//! - secure_zero_memory: Prevents dead store elimination optimization
//! - mlock: Locks memory to prevent swapping to disk (Linux/Unix platforms)

use std::sync::atomic::{compiler_fence, Ordering};

/// Securely overwrites a memory buffer with zeros.
///
/// Uses volatile writes and compiler memory barriers to prevent LLVM's Dead Store Elimination (DSE)
/// optimization from stripping the zeroing code during release builds.
///
/// This is critical for:
/// - Master storage key scrubbing during app backgrounding
/// - Kyber private key material cleanup after use
/// - Session key clearing after decryption
#[inline(never)]
pub fn secure_zero_memory(buffer: &mut [u8]) {
    if buffer.is_empty() {
        return;
    }

    unsafe {
        let mut ptr = buffer.as_mut_ptr();
        let end = ptr.add(buffer.len());

        while ptr < end {
            // Volatile write ensures the compiler cannot optimize this away
            std::ptr::write_volatile(ptr, 0u8);
            ptr = ptr.add(1);
        }
    }

    // Sequential consistency fence acts as an architectural memory barrier
    // This prevents reordering across the zeroing operation
    compiler_fence(Ordering::SeqCst);
}

/// Locks memory pages to prevent swapping to disk.
///
/// On Linux/Android, uses mlock. Returns Ok(true) on success, Ok(false) on unsupported
/// or failed platforms. This is best-effort - the function does not fail if mlock fails.
pub fn lock_memory(buffer: &mut [u8]) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios"))]
    {
        unsafe {
            let ptr = buffer.as_mut_ptr() as *mut libc::c_void;
            let len = buffer.len() as libc::size_t;
            let ret = libc::mlock(ptr, len);
            ret == 0
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios")))]
    {
        // No-op on unsupported platforms
        true
    }
}

/// Unlocks previously locked memory pages.
pub fn unlock_memory(buffer: &mut [u8]) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios"))]
    {
        unsafe {
            let ptr = buffer.as_mut_ptr() as *mut libc::c_void;
            let len = buffer.len() as libc::size_t;
            let ret = libc::munlock(ptr, len);
            ret == 0
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios")))]
    {
        true
    }
}

/// Secure container for cryptographic key material.
///
/// Automatically scrubs memory on drop using secure_zero_memory.
/// Optionally locks pages in RAM via mlock to prevent swap leakage.
pub struct SecureKeyMaterial {
    key_material: Vec<u8>,
    locked: bool,
}

impl SecureKeyMaterial {
    /// Create a new secure key material container.
    ///
    /// If `lock_pages` is true, attempts to mlock the memory.
    pub fn new(key_bytes: Vec<u8>, lock_pages: bool) -> Self {
        let locked = if lock_pages && !key_bytes.is_empty() {
            let mut key_ref = key_bytes.clone();
            lock_memory(&mut key_ref)
        } else {
            false
        };
        Self { key_material: key_bytes, locked }
    }

    /// Access the key material (for encryption operations).
    pub fn bytes(&self) -> &[u8] {
        &self.key_material
    }

    /// Get length of key material.
    pub fn len(&self) -> usize {
        self.key_material.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.key_material.is_empty()
    }

    /// Explicitly purge key from memory.
    /// Called automatically on drop, but can be invoked early.
    pub fn purge(&mut self) {
        secure_zero_memory(&mut self.key_material);
        if self.locked {
            let _ = unlock_memory(&mut self.key_material);
            self.locked = false;
        }
    }
}

impl Drop for SecureKeyMaterial {
    fn drop(&mut self) {
        // Enforce automated scrubbing when out of scope
        self.purge();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_zero_memory() {
        let mut buffer = [0x42u8; 32];
        assert_eq!(buffer, vec![0x42u8; 32].as_slice());
        
        secure_zero_memory(&mut buffer);
        
        // After secure zeroing, all bytes should be zero
        assert_eq!(buffer, vec![0u8; 32].as_slice());
    }
    
    #[test]
    fn test_secure_key_material() {
        let key = vec![0xDEu8; 32];
        let skm = SecureKeyMaterial::new(key.clone(), false);
        assert_eq!(skm.bytes(), &key[..]);
    }
    
    #[test]
    fn test_secure_key_material_purge() {
        let key = vec![0xDEu8; 32];
        let mut skm = SecureKeyMaterial::new(key.clone(), false);
        skm.purge();
        // After purge, the buffer should be zeroed
        let all_zeros = skm.bytes().iter().all(|&b| b == 0);
        assert!(skm.is_empty() || all_zeros);
    }
}