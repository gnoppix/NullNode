//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------

use base64::Engine;
use hmac::Hmac;
use sequoia_openpgp::serialize::Serialize;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;

/// In-memory cert cache: fingerprint -> armored cert.
/// Populated on first sight (TOFU) when publishers include their cert.
static CERT_CACHE: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

/// Get or initialize the cert cache.
fn cert_cache() -> std::sync::MutexGuard<'static, Option<HashMap<String, String>>> {
    CERT_CACHE.lock().expect("cert cache lock poisoned")
}

/// Store an armored cert in the cache for the given fingerprint.
pub fn cache_cert(fingerprint: &str, armored: &str) {
    let mut guard = cert_cache();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard.as_mut().unwrap().insert(fingerprint.to_uppercase(), armored.to_string());
}

/// Look up a cached cert by fingerprint.
pub fn get_cached_cert(fingerprint: &str) -> Option<String> {
    let guard = cert_cache();
    guard.as_ref()?.get(&fingerprint.to_uppercase()).cloned()
}

/// Fingerprint format: 32 or 40 hex chars (v3/v4 OpenPGP keys).
pub fn validate_fingerprint(fp: &str) -> bool {
    let len = fp.len();
    if len != 32 && len != 40 {
        return false;
    }
    fp.chars().all(|c| c.is_ascii_hexdigit())
}

/// Syntax check for null ID format: NN-XXXX-XXXX.
pub fn validate_null_id(nid: &str) -> bool {
    let parts: Vec<&str> = nid.split('-').collect();
    if parts.len() != 3 || parts[0] != "NN" {
        return false;
    }
    parts[1].len() == 4 && parts[2].len() == 4
}

/// Verify that a null ID is the correct hash of the given fingerprint.
/// This prevents an attacker from claiming someone else's null ID.
pub fn validate_null_id_strict(nid: &str, fingerprint: &str) -> bool {
    if !validate_null_id(nid) {
        return false;
    }
    if !validate_fingerprint(fingerprint) {
        return false;
    }
    constant_time_compare(&compute_null_id(fingerprint), nid)
}

/// Derive an 8-character Null ID from a GPG fingerprint.
/// blake2b(digest_size=8) → base32 → NN-XXXX-XXXX
///
/// This is a one-way mapping. The fingerprint cannot be recovered from the Null ID.
pub fn compute_null_id(fingerprint: &str) -> String {
    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;

    let mut hasher = Blake2bVar::new(8).expect("blake2b with 8 bytes is valid");
    Update::update(&mut hasher, fingerprint.as_bytes());
    let mut result = [0u8; 8];
    let _ = hasher.finalize_variable(&mut result);

    let b32 = base64::engine::general_purpose::STANDARD.encode(&result);
    let b32 = b32.trim_end_matches('=');
    let b32: String = b32.chars().take(8).collect();
    // base32 uses A-Z 2-7, which is fine for our format
    format!("NN-{}-{}", &b32[..4], &b32[4..8])
}

/// Constant-time string comparison to prevent timing attacks.
pub fn constant_time_compare(a: &str, b: &str) -> bool {
    use hmac::Mac;
    let mut mac_a = HmacSha256::new_from_slice(b"constant-time-compare").unwrap();
    mac_a.update(a.as_bytes());
    let mut mac_b = HmacSha256::new_from_slice(b"constant-time-compare").unwrap();
    mac_b.update(b.as_bytes());
    mac_a.finalize().into_bytes() == mac_b.finalize().into_bytes()
}

/// Create a base64-encoded detached OpenPGP signature over `data` using
/// the secret key from `cert` (the sender's public cert containing the
/// signing key).
///
/// SECURITY: Uses in-process Sequoia OpenPGP (no shell-out to gpg binary).
pub fn sign_data(data: &str, cert: &sequoia_openpgp::Cert) -> Result<String, String> {
    let sig_armored = nullnode_protocol::gpg::sign_detached(data, cert)?;

    // Return base64-encoded armored signature for compatibility
    Ok(base64::engine::general_purpose::STANDARD.encode(sig_armored.as_bytes()))
}

/// Verify a base64-encoded detached OpenPGP signature.
///
/// SECURITY: Uses in-process Sequoia OpenPGP verification. Verifies the
/// cryptographic signature AND that it was made by the key matching
/// `fingerprint` (case-insensitive).
///
/// The cert is looked up from the in-memory cert cache by fingerprint.
/// Returns true only if:
/// 1. The signature is cryptographically valid
/// 2. The signing key fingerprint matches the expected fingerprint
pub fn verify_signature(data: &str, b64_sig: &str, fingerprint: &str) -> bool {
    if !validate_fingerprint(fingerprint) {
        return false;
    }

    let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(b64_sig) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    let sig_armored = match String::from_utf8(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Look up the cert from the cache
    let cert_armored = match get_cached_cert(fingerprint) {
        Some(c) => c,
        None => return false,
    };

    use sequoia_openpgp::parse::Parse;
    let cert = match sequoia_openpgp::Cert::from_bytes(cert_armored.as_bytes()) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Verify fingerprint matches
    let cert_fp = nullnode_protocol::gpg::fingerprint_from_cert(&cert);
    if !cert_fp.eq_ignore_ascii_case(fingerprint) {
        return false;
    }

    match nullnode_protocol::gpg::verify_detached(&sig_armored, data, &cert) {
        Ok(valid) => valid,
        Err(_) => false,
    }
}

/// Verify a base64-encoded detached OpenPGP signature using the provided cert.
///
/// This is the preferred verify path when the caller already has the cert
/// (e.g., from the envelope payload's publisher_cert field).
pub fn verify_signature_with_cert(
    data: &str,
    b64_sig: &str,
    cert: &sequoia_openpgp::Cert,
) -> bool {
    let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(b64_sig) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    let sig_armored = match String::from_utf8(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Cache the cert for future fingerprint-only lookups
    let fp = nullnode_protocol::gpg::fingerprint_from_cert(cert);
    let mut buf = Vec::new();
    let _ = cert.serialize(&mut buf);
    cache_cert(&fp, &String::from_utf8_lossy(&buf));

    match nullnode_protocol::gpg::verify_detached(&sig_armored, data, cert) {
        Ok(valid) => valid,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_fingerprint() {
        assert!(validate_fingerprint("AABBCCDDEEFF00112233445566778899AABBCCDD"));
        assert!(validate_fingerprint("AABBCCDDEEFF00112233445566778899"));
        assert!(!validate_fingerprint("not-hex"));
        assert!(!validate_fingerprint("AABB"));
    }

    #[test]
    fn test_validate_null_id() {
        assert!(validate_null_id("NN-ABCD-EFGH"));
        assert!(!validate_null_id("XX-ABCD-EFGH"));
        assert!(!validate_null_id("NN-ABC-EFGH"));
        assert!(!validate_null_id("NN-ABCDEFGH"));
    }

    #[test]
    fn test_compute_null_id_deterministic() {
        let id1 = compute_null_id("AABBCCDDEEFF00112233445566778899AABBCCDD");
        let id2 = compute_null_id("AABBCCDDEEFF00112233445566778899AABBCCDD");
        assert_eq!(id1, id2);
        assert!(id1.starts_with("NN-"));
    }

    #[test]
    fn test_cert_cache_roundtrip() {
        cache_cert("AABBCCDDEEFF00112233445566778899AABBCCDD", "FAKE_ARMORED_CERT");
        assert_eq!(
            get_cached_cert("AABBCCDDEEFF00112233445566778899AABBCCDD"),
            Some("FAKE_ARMORED_CERT".to_string())
        );
        // Case-insensitive lookup
        assert_eq!(
            get_cached_cert("aabbccddeeff00112233445566778899aabbccdd"),
            Some("FAKE_ARMORED_CERT".to_string())
        );
    }
}
