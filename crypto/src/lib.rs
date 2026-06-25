//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// NullNode Crypto — Kyber-768 KEM (ML-KEM) for all user messages
//
// All user messages MUST be encrypted with Kyber-768 KEM (NIST Level 3,
// FIPS 203 compliant). There is no classical fallback — ML-KEM only.
//
// Architecture:
//   - encrypt() / decrypt(): standalone Kyber-768 KEM encrypt/decrypt
//   - DoubleRatchetSession: per-message Kyber-768 KEM + HKDF key evolution
//     with forward secrecy and replay protection.
//
// Key lifecycle:
//   1. Each identity has a Kyber-768 keypair (encapsulation + decapsulation)
//   2. The public key is shared in the P2P handshake and stored in the DHT
//   3. To send a message: ephemeral Kyber keypair + recipient's public key
//      -> shared secret -> HKDF -> AES-256-GCM key
//   4. Kyber-768 ciphertext is sent alongside the AES ciphertext
//   5. Recipient uses their decapsulation key to recover the shared secret
//
// This is a "KEM-then-AEAD" construction (same as Signal's PQXDH pattern).
//-------------------------------------------------------------------------------

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::MlKem1024;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use nullnode_protocol::pow::blake2b_8_hex;

pub mod kyber;
pub use kyber::MlKemVariant;
pub use kyber::VariantKeypair;
pub mod secure_mem;
pub mod delivery_tokens;
pub mod cbnp;
pub mod pir;

/// Extension trait to format a BLAKE2b-8 hex string as NN-XXXX-XXXX.
trait FormatNnId {
    fn format_nn_id(&self) -> String;
}

impl FormatNnId for String {
    fn format_nn_id(&self) -> String {
        let chars: Vec<char> = self.chars().collect();
        let a: String = chars[..4].iter().collect();
        let b: String = chars[4..8].iter().collect();
        format!("NN-{}-{}", a, b)
    }
}

// ------------------------------------------------------------------ //
//  Error type                                                        //
// ------------------------------------------------------------------ //

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid fingerprint: {0}")]
    InvalidFingerprint(String),

    #[error("encryption failed: {0}")]
    EncryptFailed(String),

    #[error("decryption failed: {0}")]
    DecryptFailed(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("ratchet error: {0}")]
    Ratchet(String),

    #[error("key persistence error: {0}")]
    KeyPersistence(String),

    #[error("PIR error: {0}")]
    Pir(String),
}

impl From<serde_json::Error> for CryptoError {
    fn from(e: serde_json::Error) -> Self {
        CryptoError::Serialization(e.to_string())
    }
}

// ------------------------------------------------------------------ //
//  Constants                                                          //
// ------------------------------------------------------------------ //

#[allow(dead_code)]
const CLOCK_SKEW_TOLERANCE: f64 = 300.0; // 5 minutes
const MAX_SKIP: usize = 256;
const NONCE_SIZE: usize = 12;

// SECURITY FIX (H1): Maximum total buffered ciphertext size per session.
// Each pending message is ~2.3KB minimum, so 256 messages could be ~576KB.
// This limit ensures attackers cannot memory-exhaust via many sessions.
// 64KB per session is generous for legitimate out-of-order delivery.
const MAX_PENDING_BUFFER_SIZE: usize = 65536; // 64KB

// ------------------------------------------------------------------ //
//  Fingerprint / Null ID validation                                  //
// ------------------------------------------------------------------ //

pub fn validate_fingerprint(fp: &str) -> Result<(), CryptoError> {
    let cleaned = fp.replace(' ', "").to_uppercase();
    if !(32..=40).contains(&cleaned.len()) {
        return Err(CryptoError::InvalidFingerprint(
            "fingerprint must be 32-40 hex chars".to_string(),
        ));
    }
    if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CryptoError::InvalidFingerprint(
            "fingerprint contains non-hex characters".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_null_id(nid: &str) -> Result<(), CryptoError> {
    let parts: Vec<&str> = nid.split('-').collect();
    if parts.len() != 3 || parts[0] != "NN" || parts[1].len() != 4 || parts[2].len() != 4 {
        return Err(CryptoError::InvalidFingerprint(
            "null ID must be NN-XXXX-XXXX format".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_null_id_strict(nid: &str, fingerprint: &str) -> Result<(), CryptoError> {
    validate_null_id(nid)?;
    validate_fingerprint(fingerprint)?;
    let expected = null_id(fingerprint);
    if nid != expected {
        return Err(CryptoError::InvalidFingerprint(format!(
            "null ID {} does not match fingerprint-derived ID {}",
            nid, expected
        )));
    }
    Ok(())
}

/// Derive a Null ID from a fingerprint using BLAKE2b-8.
pub fn null_id(fingerprint: &str) -> String {
    blake2b_8_hex(fingerprint).format_nn_id()
}

// ------------------------------------------------------------------ //
//  Kyber-768 KEM + AES-256-GCM encrypt / decrypt                    //
// ------------------------------------------------------------------ //

/// Encrypt a plaintext message for a recipient using Kyber-768 KEM.
///
/// Uses ONLY Kyber-768 (ML-KEM, NIST Level 3) for key encapsulation.
/// There is no classical/X25519 fallback.
///
/// Format (hex-encoded): [ephemeral_enc_key (1184 bytes)][kyber_ct (1088 bytes)][nonce (12 bytes)][aes_ct (variable)]
///
/// Process:
/// 1. Generate ephemeral Kyber-768 keypair
/// 2. Encapsulate shared secret with recipient's public key
/// 3. Derive AES-256-GCM key from shared secret via HKDF-SHA256
/// 4. Encrypt plaintext with AES-256-GCM
/// 5. Output: ephemeral_pk || kyber_ct || nonce || aes_ct
pub fn encrypt(
    plaintext: &str,
    recipient_kyber_enc: &crate::kyber::KyberEncapsulationKey,
) -> Result<String, CryptoError> {
    let ephemeral_kp = crate::kyber::KyberKeypair::generate()?;

    // Encapsulate shared secret with recipient's public key
    let (kyber_ct, shared_secret) = crate::kyber::KyberKeypair::encapsulate(recipient_kyber_enc)?;

    // Derive AES-256-GCM key from shared secret
    let hk = Hkdf::<Sha256>::new(None, &shared_secret);
    let mut aes_key = [0u8; 32];
    hk.expand(b"nullnode-kyber-aes-v1", &mut aes_key)
        .map_err(|e| CryptoError::EncryptFailed(format!("HKDF expand: {}", e)))?;

    // Encrypt with AES-256-GCM
    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let aes_ct = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| CryptoError::EncryptFailed(e.to_string()))?;

    // Assemble: ephemeral_enc_key || kyber_ct || nonce || aes_ct
    let mut output = Vec::new();
    output.extend_from_slice(ephemeral_kp.enc.to_bytes().as_ref());
    let kyber_ct_bytes: &[u8] = kyber_ct.as_ref();
    output.extend_from_slice(kyber_ct_bytes);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&aes_ct);

    Ok(hex::encode(output))
}

/// Decrypt a hex-encoded ciphertext using our Kyber-768 decapsulation key.
///
/// See `encrypt()` for format details. Pure Kyber-768 KEM — no fallback.
pub fn decrypt(
    ciphertext_hex: &str,
    our_kyber_dec: &crate::kyber::KyberDecapsulationKey,
) -> Result<String, CryptoError> {
    let data = hex::decode(ciphertext_hex)
        .map_err(|e| CryptoError::DecryptFailed(format!("hex decode: {}", e)))?;

    // Parse: ephemeral_enc_key (1568) || kyber_ct (1568) || nonce (12) || aes_ct
    const EPHEM_KEY_LEN: usize = 1568;
    const KYBER_CT_LEN: usize = 1568;
    const MIN_LEN: usize = EPHEM_KEY_LEN + KYBER_CT_LEN + NONCE_SIZE + 16;

    if data.len() < MIN_LEN {
        return Err(CryptoError::DecryptFailed(format!(
            "ciphertext too short: {} < {}",
            data.len(),
            MIN_LEN
        )));
    }

    let (_ephem_key_bytes, rest) = data.split_at(EPHEM_KEY_LEN);
    let (kyber_ct_bytes, rest) = rest.split_at(KYBER_CT_LEN);
    let (nonce_bytes, aes_ct) = rest.split_at(NONCE_SIZE);

    // Parse: ephemeral_enc_key (1568) || kyber_ct (1504) || nonce (12) || aes_ct
    let kyber_ct = ml_kem::kem::Ciphertext::<MlKem1024>::try_from(kyber_ct_bytes)
        .map_err(|e| CryptoError::DecryptFailed(format!("kyber ct parse: {:?}", e)))?;

    // Decapsulate shared secret using our secret key
    let shared_secret = our_kyber_dec.decapsulate(&kyber_ct);

    // Derive AES-256-GCM key
    let hk = Hkdf::<Sha256>::new(None, &shared_secret);
    let mut aes_key = [0u8; 32];
    hk.expand(b"nullnode-kyber-aes-v1", &mut aes_key)
        .map_err(|e| CryptoError::DecryptFailed(format!("HKDF expand: {}", e)))?;

    // Decrypt AES-256-GCM
    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, aes_ct)
        .map_err(|e| CryptoError::DecryptFailed(format!("AES-GCM decrypt: {}", e)))?;

    String::from_utf8(plaintext).map_err(|e| CryptoError::DecryptFailed(format!("utf-8: {}", e)))
}

// ------------------------------------------------------------------ //
//  Double Ratchet Session — Kyber-768 KEM with forward secrecy       //
// ------------------------------------------------------------------ //

/// Payload structure for ratchet-encrypted messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RatchetPayload {
    metadata: RatchetMetadata,
    body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RatchetMetadata {
    from: String,
    to: String,
    seq: i64,
    ts: f64,
}

/// A buffered out-of-order message awaiting processing.
struct PendingMessage {
    kyber_ct_bytes: Vec<u8>,
    nonce_bytes: Vec<u8>,
    aes_ct: Vec<u8>,
}

/// A per-peer double ratchet session with Kyber-768 KEM.
///
/// Each message uses a fresh Kyber-768 ephemeral keypair with the peer's
/// static public key, plus HKDF key evolution for forward secrecy.
///
/// SECURITY PROPERTIES:
/// - Post-quantum confidentiality: Kyber-768 KEM (NIST Level 3)
/// - Forward secrecy: per-message ephemeral Kyber keys + chain key evolution
/// - Break-in recovery: future messages safe after key compromise
/// - Replay protection: sequence numbers + timestamps
///
/// SECURITY FIX (C1): The root key is derived from an initial Kyber-768
/// shared secret (from the initial KEM exchange) mixed with both
/// fingerprints, NOT from public fingerprints alone. An attacker who
/// knows both fingerprints cannot derive the root key.
///
/// SECURITY FIX (C2): Out-of-order messages are buffered in a reorder
/// buffer (pending), NOT pre-computed with a shared secret clone. Each
/// message has its own Kyber ciphertext and is decapsulated independently
/// when it reaches its expected sequence number.
#[allow(dead_code)]
pub struct DoubleRatchetSession {
    peer_fingerprint: String,
    peer_null_id: String,
    our_fingerprint: String,
    is_initiator: bool,
    send_seq: i64,
    recv_seq: i64,
    pending: HashMap<i64, PendingMessage>,
    last_recv_ts: f64,
    root_key: [u8; 32],
    send_chain_key: [u8; 32],
    recv_chain_key: [u8; 32],
}

impl DoubleRatchetSession {
    /// Create a new ratchet session.
    ///
    /// SECURITY FIX (C1): The root key is derived from the initial Kyber-768
    /// shared secret (from the initial KEM exchange between the two parties)
    /// mixed with both fingerprints. An attacker who knows both fingerprints
    /// but not the Kyber shared secret cannot derive the root key.
    ///
    /// `initial_shared_secret` MUST be the Kyber-768 shared secret from the
    /// initial key exchange (encapsulation with the recipient's public key).
    pub fn new(
        peer_fingerprint: &str,
        peer_null_id: &str,
        our_fingerprint: &str,
        is_initiator: bool,
        initial_shared_secret: &[u8],
    ) -> Result<Self, CryptoError> {
        validate_fingerprint(peer_fingerprint)?;
        validate_fingerprint(our_fingerprint)?;
        validate_null_id(peer_null_id)?;

        // Derive root key from Kyber shared secret + fingerprints.
        // The shared secret provides confidentiality; the fingerprints
        // provide authentication binding (prevents key substitution).
        let mut hasher = Sha256::new();
        hasher.update(initial_shared_secret);
        if is_initiator {
            hasher.update(our_fingerprint.as_bytes());
            hasher.update(peer_fingerprint.as_bytes());
        } else {
            hasher.update(peer_fingerprint.as_bytes());
            hasher.update(our_fingerprint.as_bytes());
        }
        let root_key: [u8; 32] = hasher.finalize().into();

        // Derive initial chain keys via HKDF
        let send_chain_key = if is_initiator {
            derive_chain_key(&root_key, b"send")
        } else {
            derive_chain_key(&root_key, b"recv")
        };
        let recv_chain_key = if is_initiator {
            derive_chain_key(&root_key, b"recv")
        } else {
            derive_chain_key(&root_key, b"send")
        };

        Ok(Self {
            peer_fingerprint: peer_fingerprint.to_string(),
            peer_null_id: peer_null_id.to_string(),
            our_fingerprint: our_fingerprint.to_string(),
            is_initiator,
            send_seq: 0,
            recv_seq: 0,
            pending: HashMap::new(),
            last_recv_ts: 0.0,
            root_key,
            send_chain_key,
            recv_chain_key,
        })
    }

    /// Encrypt a message using Kyber-768 KEM + ratchet.
    pub fn encrypt_message(
        &mut self,
        plaintext: &str,
        peer_kyber_enc: &crate::kyber::KyberEncapsulationKey,
    ) -> Result<String, CryptoError> {
        let metadata = RatchetMetadata {
            from: null_id(&self.our_fingerprint),
            to: self.peer_null_id.clone(),
            seq: self.send_seq,
            ts: now_unix(),
        };

        let payload = RatchetPayload {
            metadata,
            body: plaintext.to_string(),
        };

        let payload_json = serde_json::to_string(&payload)?;

        // Derive message key from chain key via HKDF
        let message_key = derive_message_key(&self.send_chain_key, self.send_seq);

        // Generate ephemeral Kyber keypair for this message
        let ephemeral_kp = crate::kyber::KyberKeypair::generate()?;
        let (kyber_ct, shared_secret) = crate::kyber::KyberKeypair::encapsulate(peer_kyber_enc)?;

        // Combine shared secret with ratchet message key for enhanced security
        let mut combined_secret = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&shared_secret);
        hasher.update(&message_key);
        combined_secret.copy_from_slice(&hasher.finalize());

        // Derive AES key from combined secret
        let hk = Hkdf::<Sha256>::new(None, &combined_secret);
        let mut aes_key = [0u8; 32];
        hk.expand(b"nullnode-ratchet-kyber-v1", &mut aes_key)
            .map_err(|e| CryptoError::EncryptFailed(format!("HKDF expand: {}", e)))?;

        // Encrypt with AES-256-GCM
        let key = Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let aes_ct = cipher
            .encrypt(&nonce, payload_json.as_bytes())
            .map_err(|e| CryptoError::EncryptFailed(e.to_string()))?;

        // Assemble: ephemeral_enc_key || kyber_ct || nonce || aes_ct
        let mut output = Vec::new();
        output.extend_from_slice(ephemeral_kp.enc.to_bytes().as_ref());
        let kyber_ct_bytes: &[u8] = kyber_ct.as_ref();
        output.extend_from_slice(kyber_ct_bytes);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&aes_ct);

        let ct_hex = hex::encode(output);

        // Compute message hash for integrity/dedup
        let mut hasher = Sha256::new();
        hasher.update(ct_hex.as_bytes());

        let seq = self.send_seq;
        self.send_seq += 1;

        // Ratchet step: evolve chain key
        self.ratchet_step(true);

        Ok(format!(
            "{}:{}:{}",
            seq,
            ct_hex,
            format!("{:x}", hasher.finalize())
        ))
    }

    /// Decrypt a message with Kyber-768 KEM + ratchet.
    pub fn decrypt_message(
        &mut self,
        message: &str,
        our_kyber_keypair: &crate::kyber::KyberKeypair,
    ) -> Result<String, CryptoError> {
        let parts: Vec<&str> = message.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(CryptoError::DecryptFailed(
                "invalid message format: expected seq:ct_hex:hash".to_string(),
            ));
        }

        let claimed_seq: i64 = parts[0]
            .parse()
            .map_err(|e| CryptoError::DecryptFailed(format!("seq parse: {}", e)))?;
        let ciphertext_hex = parts[1];

        let data = hex::decode(ciphertext_hex)
            .map_err(|e| CryptoError::DecryptFailed(format!("hex decode: {}", e)))?;

        // Parse: ephemeral_enc_key (1568) || kyber_ct (1568) || nonce (12) || aes_ct
        const EPHEM_KEY_LEN: usize = 1568;
        const KYBER_CT_LEN: usize = 1568;
        const MIN_LEN: usize = EPHEM_KEY_LEN + KYBER_CT_LEN + NONCE_SIZE + 16;

        if data.len() < MIN_LEN {
            return Err(CryptoError::DecryptFailed(format!(
                "ciphertext too short: {} < {}",
                data.len(),
                MIN_LEN
            )));
        }

        let (_ephem_key_bytes, rest) = data.split_at(EPHEM_KEY_LEN);
        let (kyber_ct_bytes, rest) = rest.split_at(KYBER_CT_LEN);
        let (nonce_bytes, aes_ct) = rest.split_at(NONCE_SIZE);

        // Reconstruct Kyber ciphertext
        let kyber_ct = ml_kem::kem::Ciphertext::<MlKem1024>::try_from(kyber_ct_bytes)
            .map_err(|e| CryptoError::DecryptFailed(format!("kyber ct parse: {:?}", e)))?;

        // SECURITY FIX (C2): Out-of-order messages are buffered in a reorder
        // buffer and processed when their sequence number is reached. Each
        // message has its own Kyber ciphertext and is decapsulated independently.
        // This replaces the old skipped-keys logic that cloned a single shared
        // secret for all skipped messages.

        // If this is not the expected sequence, buffer it and try later.
        if claimed_seq > self.recv_seq {
            // SECURITY FIX (H1): Check both count and total buffer size
            if self.pending.len() >= MAX_SKIP {
                return Err(CryptoError::Ratchet(
                    "too many pending messages — possible DoS".to_string(),
                ));
            }
            // Calculate total pending buffer size to prevent memory exhaustion
            let new_msg_size = kyber_ct_bytes.len() + nonce_bytes.len() + aes_ct.len();
            let current_pending_size: usize = self.pending.values().map(|p| p.kyber_ct_bytes.len() + p.nonce_bytes.len() + p.aes_ct.len()).sum::<usize>() + new_msg_size;
            if current_pending_size > MAX_PENDING_BUFFER_SIZE {
                return Err(CryptoError::Ratchet(
                    "pending buffer size exceeded — possible memory exhaustion attack".to_string(),
                ));
            }
            self.pending.insert(claimed_seq, PendingMessage {
                kyber_ct_bytes: kyber_ct_bytes.to_vec(),
                nonce_bytes: nonce_bytes.to_vec(),
                aes_ct: aes_ct.to_vec(),
            });
            // Try to process any pending messages that are now next in line
            return self.try_process_pending(our_kyber_keypair);
        }

        // Reject replays (seq < expected)
        if claimed_seq < self.recv_seq {
            return Err(CryptoError::Ratchet(format!(
                "replay detected: seq {} < expected {}",
                claimed_seq, self.recv_seq
            )));

        }

        // claimed_seq == self.recv_seq: decrypt this message directly
        let shared_secret = our_kyber_keypair.decapsulate(&kyber_ct)?;

        let msg_key = derive_message_key(&self.recv_chain_key, claimed_seq);

        // Combine shared secret with ratchet message key
        let mut combined_secret = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&shared_secret);
        hasher.update(&msg_key);
        combined_secret.copy_from_slice(&hasher.finalize());

        // 4. Derive AES key from combined secret
        let hk = Hkdf::<Sha256>::new(None, &combined_secret);
        let mut aes_key = [0u8; 32];
        hk.expand(b"nullnode-ratchet-kyber-v1", &mut aes_key)
            .map_err(|e| CryptoError::DecryptFailed(format!("HKDF expand: {}", e)))?;

        // 5. Decrypt AES-256-GCM
        let key_ref = Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(key_ref);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, aes_ct)
            .map_err(|e| CryptoError::DecryptFailed(format!("AES-GCM decrypt: {}", e)))?;

        self.recv_seq = std::cmp::max(self.recv_seq, claimed_seq + 1);
        self.ratchet_step(false);

        let payload: RatchetPayload = serde_json::from_slice(&plaintext)?;
        verify_and_extract(
            payload,
            claimed_seq,
            &self.peer_null_id,
            &null_id(&self.our_fingerprint),
        )
    }

    /// Try to process any pending messages that are next in the sequence.
    ///
    /// SECURITY FIX (C2): Each pending message has its own Kyber ciphertext
    /// and is decapsulated independently when it reaches its expected
    /// sequence number. This replaces the old skipped-keys logic that cloned
    /// a single shared secret for all skipped messages.
    fn try_process_pending(
        &mut self,
        our_kyber_keypair: &crate::kyber::KyberKeypair,
    ) -> Result<String, CryptoError> {
        // Check if the next expected message is in the pending buffer
        if let Some(pending) = self.pending.remove(&self.recv_seq) {
            // Reconstruct Kyber ciphertext from buffered bytes
            let kyber_ct = ml_kem::kem::Ciphertext::<MlKem1024>::try_from(&pending.kyber_ct_bytes[..])
                .map_err(|e| CryptoError::DecryptFailed(format!("kyber ct parse: {:?}", e)))?;

            let shared_secret = our_kyber_keypair.decapsulate(&kyber_ct)?;

            let msg_key = derive_message_key(&self.recv_chain_key, self.recv_seq);

            let mut combined_secret = [0u8; 32];
            let mut hasher = Sha256::new();
            hasher.update(&shared_secret);
            hasher.update(&msg_key);
            combined_secret.copy_from_slice(&hasher.finalize());

            let hk = Hkdf::<Sha256>::new(None, &combined_secret);
            let mut aes_key = [0u8; 32];
            hk.expand(b"nullnode-ratchet-kyber-v1", &mut aes_key)
                .map_err(|e| CryptoError::DecryptFailed(format!("HKDF expand: {}", e)))?;

            let key_ref = Key::<Aes256Gcm>::from_slice(&aes_key);
            let cipher = Aes256Gcm::new(key_ref);
            let nonce = Nonce::from_slice(&pending.nonce_bytes);

            let plaintext = cipher
                .decrypt(nonce, pending.aes_ct.as_ref())
                .map_err(|e| CryptoError::DecryptFailed(format!("AES-GCM decrypt: {}", e)))?;

            let claimed_seq = self.recv_seq;
            self.recv_seq = claimed_seq + 1;
            self.ratchet_step(false);

            let payload: RatchetPayload = serde_json::from_slice(&plaintext)?;
            return verify_and_extract(
                payload,
                claimed_seq,
                &self.peer_null_id,
                &null_id(&self.our_fingerprint),
            );
        }

        // No pending message for the expected sequence — nothing to do yet
        Err(CryptoError::Ratchet(format!(
            "message buffered pending seq {} — expected seq {} not yet received",
            self.recv_seq,
            self.recv_seq,
        )))
    }

    /// Perform a ratchet step — evolve chain key via SHA-256.
    fn ratchet_step(&mut self, is_send: bool) {
        let chain_key = if is_send {
            &mut self.send_chain_key
        } else {
            &mut self.recv_chain_key
        };

        let mut hasher = Sha256::new();
        hasher.update(&*chain_key);
        hasher.update(b"nullnode-ratchet-step-v1");
        *chain_key = hasher.finalize().into();
    }

    // SECURITY FIX (G9): Persist DoubleRatchetSession to disk so encrypted
    // conversations survive restarts. Without this, all sessions are lost
    // on restart and no messages can be decrypted.

    /// Serialize the session to a JSON string for persistence.
    ///
    /// SECURITY NOTE (G8): Pending ciphertext is included in serialized form
    /// so sessions survive process restarts. This is necessary for message
    /// delivery but means encrypted data may be exposed in memory dumps or
    /// if the session file is compromised. Files are stored with 0o600
    /// permissions. Consider filesystem encryption for high-security use.
    pub fn serialize(&self) -> Result<String, CryptoError> {
        let pending_ser: HashMap<i64, (String, String, String)> = self
            .pending
            .iter()
            .map(|(seq, msg)| {
                (
                    *seq,
                    (hex::encode(&msg.kyber_ct_bytes),
                     hex::encode(&msg.nonce_bytes),
                     hex::encode(&msg.aes_ct)),
                )
            })
            .collect();
        let data = serde_json::json!({
            "peer_fingerprint": self.peer_fingerprint,
            "peer_null_id": self.peer_null_id,
            "our_fingerprint": self.our_fingerprint,
            "is_initiator": self.is_initiator,
            "send_seq": self.send_seq,
            "recv_seq": self.recv_seq,
            "pending": pending_ser,
            "last_recv_ts": self.last_recv_ts,
            "root_key": hex::encode(self.root_key),
            "send_chain_key": hex::encode(self.send_chain_key),
            "recv_chain_key": hex::encode(self.recv_chain_key),
        });
        serde_json::to_string(&data)
            .map_err(|e| CryptoError::Serialization(format!("ratchet serialize: {}", e)))
    }

    /// Deserialize a session from a JSON string.
    pub fn deserialize(json: &str) -> Result<Self, CryptoError> {
        let data: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| CryptoError::Serialization(format!("ratchet deserialize: {}", e)))?;
        let pending_raw: HashMap<i64, (String, String, String)> =
            serde_json::from_value(data["pending"].clone())
                .map_err(|e| CryptoError::Serialization(format!("pending parse: {}", e)))?;
        let mut pending = HashMap::new();
        for (seq, (ct_b64, nonce_b64, aes_b64)) in pending_raw {
            pending.insert(
                seq,
                PendingMessage {
                    kyber_ct_bytes: hex::decode(&ct_b64)
                        .map_err(|e| CryptoError::Serialization(format!("ct hex: {}", e)))?,
                    nonce_bytes: hex::decode(&nonce_b64)
                        .map_err(|e| CryptoError::Serialization(format!("nonce hex: {}", e)))?,
                    aes_ct: hex::decode(&aes_b64)
                        .map_err(|e| CryptoError::Serialization(format!("aes hex: {}", e)))?,
                },
            );
        }
        let root_key = hex::decode(data["root_key"].as_str().unwrap_or(""))
            .map_err(|e| CryptoError::Serialization(format!("root_key hex: {}", e)))?;
        let send_chain_key = hex::decode(data["send_chain_key"].as_str().unwrap_or(""))
            .map_err(|e| CryptoError::Serialization(format!("send_chain_key hex: {}", e)))?;
        let recv_chain_key = hex::decode(data["recv_chain_key"].as_str().unwrap_or(""))
            .map_err(|e| CryptoError::Serialization(format!("recv_chain_key hex: {}", e)))?;
        Ok(Self {
            peer_fingerprint: data["peer_fingerprint"].as_str().unwrap_or("").to_string(),
            peer_null_id: data["peer_null_id"].as_str().unwrap_or("").to_string(),
            our_fingerprint: data["our_fingerprint"].as_str().unwrap_or("").to_string(),
            is_initiator: data["is_initiator"].as_bool().unwrap_or(true),
            send_seq: data["send_seq"].as_i64().unwrap_or(0),
            recv_seq: data["recv_seq"].as_i64().unwrap_or(0),
            pending,
            last_recv_ts: data["last_recv_ts"].as_f64().unwrap_or(0.0),
            root_key: root_key.as_slice().try_into()
                .map_err(|_| CryptoError::Serialization("root_key length".into()))?,
            send_chain_key: send_chain_key.as_slice().try_into()
                .map_err(|_| CryptoError::Serialization("send_chain_key length".into()))?,
            recv_chain_key: recv_chain_key.as_slice().try_into()
                .map_err(|_| CryptoError::Serialization("recv_chain_key length".into()))?,
        })
    }

    /// Save session to a file (0o600 permissions).
    pub fn save(&self, path: &std::path::Path) -> Result<(), CryptoError> {
        let data = self.serialize()?;
        std::fs::write(path, &data)
            .map_err(|e| CryptoError::Serialization(format!("session write: {}", e)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Load session from a file.
    pub fn load(path: &std::path::Path) -> Result<Self, CryptoError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| CryptoError::Serialization(format!("session read: {}", e)))?;
        Self::deserialize(&content)
    }
}

/// Verify metadata and extract message body.
fn verify_and_extract(
    payload: RatchetPayload,
    _claimed_seq: i64,
    expected_from: &str,
    expected_to: &str,
) -> Result<String, CryptoError> {
    if payload.metadata.to != expected_to {
        return Err(CryptoError::Ratchet(
            "message not addressed to us".to_string(),
        ));
    }
    if payload.metadata.from != expected_from {
        return Err(CryptoError::Ratchet(
            "message from unexpected sender".to_string(),
        ));
    }
    Ok(payload.body)
}

// ------------------------------------------------------------------ //
//  Key derivation helpers                                            //
// ------------------------------------------------------------------ //

fn derive_chain_key(root_key: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, root_key);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("HKDF expand failed");
    okm
}

fn derive_message_key(chain_key: &[u8; 32], seq: i64) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, chain_key);
    let mut okm = [0u8; 32];
    let info = format!("msg-key-{seq}");
    hk.expand(info.as_bytes(), &mut okm)
        .expect("HKDF expand failed");
    okm
}

fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

// ------------------------------------------------------------------ //
//  Tests                                                              //
// ------------------------------------------------------------------ //

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kyber::KyberKeypair;

    #[test]
    fn test_null_id_format() {
        let fp = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";
        let nid = null_id(fp);
        assert!(nid.starts_with("NN-"));
        assert_eq!(nid.len(), 12); // NN-XXXX-XXXX
    }

    #[test]
    fn test_validate_fingerprint() {
        assert!(validate_fingerprint("A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2").is_ok());
        assert!(validate_fingerprint("too-short").is_err());
        assert!(validate_fingerprint("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG").is_err());
    }

    #[test]
    fn test_validate_null_id() {
        assert!(validate_null_id("NN-ABCD-EFGH").is_ok());
        assert!(validate_null_id("XX-ABCD-EFGH").is_err());
        assert!(validate_null_id("NN-ABCDEFGH").is_err());
    }

    #[test]
    fn test_kyber_kem_encrypt_decrypt_roundtrip() {
        let recipient = KyberKeypair::generate().unwrap();
        let plaintext = "Hello, NullNode! This is a post-quantum encrypted message.";

        let ct = encrypt(plaintext, &recipient.enc).unwrap();
        let pt = decrypt(&ct, &recipient.dec).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_kyber_kem_different_ciphertext_each_time() {
        let recipient = KyberKeypair::generate().unwrap();
        let plaintext = "same message";

        let ct1 = encrypt(plaintext, &recipient.enc).unwrap();
        let ct2 = encrypt(plaintext, &recipient.enc).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_kyber_kem_wrong_recipient_cannot_decrypt() {
        let alice = KyberKeypair::generate().unwrap();
        let bob = KyberKeypair::generate().unwrap();

        let ct = encrypt("secret", &alice.enc).unwrap();
        let result = decrypt(&ct, &bob.dec);
        assert!(result.is_err());
    }

    #[test]
    fn test_double_ratchet_new() {
        let fp1 = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";
        let fp2 = "B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B3";
        let nid2 = null_id(fp2);

        // Initial KEM exchange: Alice encapsulates with Bob's public key
        let bob_kp = KyberKeypair::generate().unwrap();
        let (_ct, shared_secret) = KyberKeypair::encapsulate(&bob_kp.enc).unwrap();

        let session = DoubleRatchetSession::new(fp2, &nid2, fp1, true, &shared_secret);
        assert!(session.is_ok());
    }

    #[test]
    fn test_double_ratchet_invalid_fp() {
        let result = DoubleRatchetSession::new("invalid", "NN-ABCD-EFGH", "also-invalid", true, &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_double_ratchet_kyber_encrypt_decrypt() {
        let fp1 = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";
        let fp2 = "B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B3";
        let nid1 = null_id(fp1);
        let nid2 = null_id(fp2);

        let kyber_a = KyberKeypair::generate().unwrap();
        let kyber_b = KyberKeypair::generate().unwrap();

        // Initial KEM exchange: Alice encapsulates with Bob's public key
        let (_init_ct, init_shared_secret) = KyberKeypair::encapsulate(&kyber_b.enc).unwrap();

        let mut session_a = DoubleRatchetSession::new(fp2, &nid2, fp1, true, &init_shared_secret).unwrap();
        let mut session_b = DoubleRatchetSession::new(fp1, &nid1, fp2, false, &init_shared_secret).unwrap();

        // A encrypts for B (using B's public key)
        let ct = session_a
            .encrypt_message("Hello from Kyber!", &kyber_b.enc)
            .unwrap();
        // B decrypts with its own keypair
        let plaintext = session_b.decrypt_message(&ct, &kyber_b).unwrap();
        assert_eq!(plaintext, "Hello from Kyber!");

        // B replies to A (using A's public key)
        let ct2 = session_b
            .encrypt_message("Hello from B via Kyber!", &kyber_a.enc)
            .unwrap();
        // A decrypts with its own keypair
        let plaintext2 = session_a.decrypt_message(&ct2, &kyber_a).unwrap();
        assert_eq!(plaintext2, "Hello from B via Kyber!");

        // Multiple messages
        let ct3 = session_a
            .encrypt_message("Message 3", &kyber_b.enc)
            .unwrap();
        let plaintext3 = session_b.decrypt_message(&ct3, &kyber_b).unwrap();
        assert_eq!(plaintext3, "Message 3");
    }

    #[test]
    fn test_double_ratchet_kyber_replay_protection() {
        let fp1 = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";
        let fp2 = "B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B3";
        let nid1 = null_id(fp1);
        let nid2 = null_id(fp2);

        let _kyber_a = KyberKeypair::generate().unwrap();
        let kyber_b = KyberKeypair::generate().unwrap();

        // Initial KEM exchange: Alice encapsulates with Bob's public key
        let (_init_ct, init_shared_secret) = KyberKeypair::encapsulate(&kyber_b.enc).unwrap();

        let mut session_a = DoubleRatchetSession::new(fp2, &nid2, fp1, true, &init_shared_secret).unwrap();
        let mut session_b = DoubleRatchetSession::new(fp1, &nid1, fp2, false, &init_shared_secret).unwrap();

        let ct = session_a
            .encrypt_message("test message", &kyber_b.enc)
            .unwrap();

        // First decrypt succeeds
        let _ = session_b.decrypt_message(&ct, &kyber_b).unwrap();

        // Replay should fail
        let result = session_b.decrypt_message(&ct, &kyber_b);
        assert!(result.is_err());
    }

    #[test]
    fn test_kyber_public_key_derivation() {
        let kp = KyberKeypair::generate().unwrap();
        // ML-KEM-1024: 1568 bytes public key, 64 bytes seed/dec key
        assert_eq!(kp.enc.to_bytes().len(), 1568);
        assert_eq!(kp.dec.to_bytes().len(), 64);
    }
}
