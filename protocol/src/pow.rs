//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};

use crate::constants;

/// Count leading zero bits in a byte slice.
fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut bits = 0u32;
    for &byte in hash {
        if byte == 0 {
            bits += 8;
        } else {
            let mut b = byte;
            while b > 0 && (b & 0x80) == 0 {
                bits += 1;
                b <<= 1;
            }
            break;
        }
    }
    bits
}

/// Custom error type for PoW operations.
#[derive(Debug, thiserror::Error)]
pub enum PowError {
    #[error("Argon2id parameter error: {0}")]
    Argon2Params(String),
    #[error("Argon2id hashing error: {0}")]
    Argon2Hash(String),
    #[error("PoW difficulty too high - no valid nonce found within max attempts")]
    DifficultyTooHigh,
}

/// Verify Argon2id PoW: check that hash has at least `difficulty` leading zero bits.
///
/// SECURITY: Argon2id-only. No SHA-256 fallback - this ensures memory-hard
/// PoW is always used, maintaining GPU/ASIC resistance.
pub fn pow_check(data: &str, nonce: u64, difficulty: u32) -> Result<bool, PowError> {
    let params = Params::new(
        constants::DHT_POW_MEMORY_COST,
        constants::DHT_POW_TIME_COST,
        constants::DHT_POW_PARALLELISM,
        Some(constants::DHT_POW_HASH_LEN),
    ).map_err(|e| PowError::Argon2Params(e.to_string()))?;

    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let secret = format!("{}{}", data, nonce);
    let mut raw = [0u8; constants::DHT_POW_HASH_LEN];
    hasher.hash_password_into(secret.as_bytes(), constants::POW_SALT, &mut raw)
        .map_err(|e| PowError::Argon2Hash(e.to_string()))?;

    Ok(leading_zero_bits(&raw) >= difficulty)
}

/// Find a nonce such that Argon2id(data, nonce) has >= `difficulty` leading zero bits.
///
/// SECURITY: Argon2id-only. Returns error if memory allocation fails instead
/// of falling back to SHA-256 hashcash.
pub fn pow_solve(
    data: &str,
    difficulty: u32,
    max_attempts: u64,
) -> Result<Option<u64>, PowError> {
    let params = Params::new(
        constants::DHT_POW_MEMORY_COST,
        constants::DHT_POW_TIME_COST,
        constants::DHT_POW_PARALLELISM,
        Some(constants::DHT_POW_HASH_LEN),
    ).map_err(|e| PowError::Argon2Params(e.to_string()))?;

    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    for nonce in 0..max_attempts {
        let secret = format!("{}{}", data, nonce);
        let mut raw = [0u8; constants::DHT_POW_HASH_LEN];
        hasher.hash_password_into(secret.as_bytes(), constants::POW_SALT, &mut raw)
            .map_err(|e| PowError::Argon2Hash(e.to_string()))?;

        if leading_zero_bits(&raw) >= difficulty {
            return Ok(Some(nonce));
        }
    }
    Ok(None)
}

// SECURITY: SHA-256 PoW functions removed - they provided an insecure fallback path
// that could be exploited to bypass GPU/ASIC-resistant Argon2id memory-hard PoW.
// If Argon2id memory allocation fails, the operation fails hard rather than falling
// back to fast hashcash. This maintains the ~500,000x botnet throughput reduction.

/// Compute SHA-256 hex digest.
///
/// NOTE: This is kept for fingerprinting and other non-PoW uses. It is NOT used
/// for proof-of-work anymore - use `pow_check` and `pow_solve` for PoW operations.
pub fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, data.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute BLAKE2b-8 hex digest.
pub fn blake2b_8_hex(data: &str) -> String {
    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;

    let mut hasher = Blake2bVar::new(8).expect("blake2b with 8 bytes is valid");
    Update::update(&mut hasher, data.as_bytes());
    let mut result = [0u8; 8];
    let _ = hasher.finalize_variable(&mut result);
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_pow_low_difficulty() {
        // Difficulty 4 should find a nonce very quickly
        let nonce = pow_solve("test", 4, 10000).unwrap().unwrap();
        assert!(pow_check("test", nonce, 4).unwrap());
    }

    #[test]
    fn test_sha256_hex() {
        let h = sha256_hex("hello world");
        assert_eq!(
            h,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_blake2b_8_hex() {
        let h = blake2b_8_hex("test_fingerprint");
        assert_eq!(h.len(), 16); // 8 bytes = 16 hex chars
    }
}