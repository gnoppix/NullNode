//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// NullNode Kyber-768 KEM — Post-quantum key exchange for test messages only
//
// Uses ml-kem crate (pure Rust, FIPS 203 compliant).
// Kyber-768 provides NIST Level 3 quantum-resistant key encapsulation.
//
// SECURITY MODEL:
// - Kyber-768 wraps a shared secret that encrypts a TEST payload only.
// - Pure (non-test) messages use AES-256-GCM via DoubleRatchetSession.
// - No one can decrypt pure messages via Kyber — they are separate cipher systems.
//-------------------------------------------------------------------------------

use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::MlKem768;
use ml_kem::KeyExport;
use ml_kem::TryKeyInit;
use base64::Engine;

use crate::CryptoError;

/// Kyber-768 encapsulation (public) key.
pub type KyberEncapsulationKey = ml_kem::kem::EncapsulationKey<MlKem768>;

/// Kyber-768 decapsulation (secret) key.
pub type KyberDecapsulationKey = ml_kem::kem::DecapsulationKey<MlKem768>;

/// Kyber-768 ciphertext (1088 bytes).
pub type KyberCiphertext = ml_kem::kem::Ciphertext<MlKem768>;

/// Kyber-768 shared secret (32 bytes).
pub type KyberSharedSecret = ml_kem::kem::SharedKey<MlKem768>;

/// Encode a Kyber encapsulation key as base64 for wire transport.
pub fn encode_enc_key(key: &KyberEncapsulationKey) -> String {
    let bytes = key.to_bytes();
    base64::engine::general_purpose::STANDARD.encode(bytes.as_slice())
}

/// Decode a base64-encoded Kyber encapsulation key.
pub fn decode_enc_key(b64: &str) -> Result<KyberEncapsulationKey, CryptoError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| CryptoError::KeyPersistence(format!("base64 decode: {}", e)))?;
    ml_kem::kem::EncapsulationKey::<MlKem768>::new_from_slice(bytes.as_slice())
        .map_err(|_| CryptoError::KeyPersistence("invalid enc key bytes".into()))
}

/// A Kyber-768 keypair for post-quantum key exchange.
#[derive(Debug, Clone)]
pub struct KyberKeypair {
    pub enc: KyberEncapsulationKey,
    pub dec: KyberDecapsulationKey,
}

impl KyberKeypair {
    /// Generate a new Kyber-768 keypair using OS randomness.
    pub fn generate() -> Result<Self, CryptoError> {
        let (dec, enc) = MlKem768::generate_keypair();
        Ok(Self { enc, dec })
    }

    /// Encapsulate a shared secret for the given public key.
    /// Returns (ciphertext, shared_secret).
    pub fn encapsulate(
        enc_key: &KyberEncapsulationKey,
    ) -> Result<(KyberCiphertext, KyberSharedSecret), CryptoError> {
        let (ct, ss) = enc_key.encapsulate();
        Ok((ct, ss))
    }

    /// Decapsulate a ciphertext using our secret key.
    /// Returns the shared secret.
    pub fn decapsulate(
        &self,
        ciphertext: &KyberCiphertext,
    ) -> Result<KyberSharedSecret, CryptoError> {
        let ss = self.dec.decapsulate(ciphertext);
        Ok(ss)
    }

    // SECURITY FIX (G10): Persist Kyber keypair to disk so the same key
    // is reused across sessions. Without this, the DHT address record
    // (which contains the Kyber public key) becomes stale after restart
    // because a new keypair is generated each time.

    /// Save the Kyber keypair to a file (encoded as hex).
    /// The file is written with 0o600 permissions (owner-only read).
    pub fn save(&self, path: &std::path::Path) -> Result<(), CryptoError> {
        let enc_bytes = self.enc.to_bytes();
        let dec_bytes = self.dec.to_bytes();
        let data = serde_json::json!({
            "enc": hex::encode(enc_bytes),
            "dec": hex::encode(dec_bytes),
        });
        std::fs::write(path, data.to_string())
            .map_err(|e| CryptoError::KeyPersistence(format!("write failed: {}", e)))?;
        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Load a Kyber keypair from a file.
    pub fn load(path: &std::path::Path) -> Result<Self, CryptoError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| CryptoError::KeyPersistence(format!("read failed: {}", e)))?;
        let data: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| CryptoError::KeyPersistence(format!("parse failed: {}", e)))?;
        let enc_hex = data["enc"]
            .as_str()
            .ok_or_else(|| CryptoError::KeyPersistence("missing enc field".into()))?;
        let dec_hex = data["dec"]
            .as_str()
            .ok_or_else(|| CryptoError::KeyPersistence("missing dec field".into()))?;
        let enc_bytes = hex::decode(enc_hex)
            .map_err(|e| CryptoError::KeyPersistence(format!("enc hex decode: {}", e)))?;
        let dec_bytes = hex::decode(dec_hex)
            .map_err(|e| CryptoError::KeyPersistence(format!("dec hex decode: {}", e)))?;
        // Reconstruct keys: enc uses KeyInit::new_from_slice, dec uses from_seed
        let enc_key = ml_kem::kem::EncapsulationKey::<MlKem768>::new_from_slice(enc_bytes.as_slice())
            .map_err(|_| CryptoError::KeyPersistence("invalid enc key bytes".into()))?;
        // ml_kem 0.3.x from_seed expects seed as Array<u8, U64>
        let dec_key = ml_kem::kem::DecapsulationKey::<MlKem768>::from_seed(dec_bytes.as_slice().try_into()
            .map_err(|_| CryptoError::KeyPersistence("invalid seed length".into()))?);
        Ok(Self { enc: enc_key, dec: dec_key })
    }

    pub fn load_or_generate(path: &std::path::Path) -> Result<Self, CryptoError> {
        if path.exists() {
            Self::load(path)
        } else {
            let kp = Self::generate()?;
            kp.save(path)?;
            Ok(kp)
        }
    }
}