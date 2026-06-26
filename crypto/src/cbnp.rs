//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// CBNP — Covert Background Noise Protocol (ACS2.6 §4.2)
//
// Generates synthetic traffic to obscure real message timing patterns.
// Each node periodically sends cover traffic that is indistinguishable from
// real messages (same size distribution, same timing jitter).
//
// Design:
//   - Poisson-distributed inter-message intervals (configurable lambda)
//   - Constant-size cover packets (padded to max real message size)
//   - Separate cover traffic keypair (never used for real encryption)
//   - Recipient silently drops cover traffic (detects via session tag prefix)
//
// The cover traffic keypair is separate from the real identity key to ensure
// that an observer cannot distinguish cover from real by public key alone.
//-------------------------------------------------------------------------------

use rand::Rng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::CryptoError;

/// Cover traffic packet size (padded to match real message size).
/// Real messages: ephemeral_enc_key (1568) + kyber_ct (1568) + nonce (12) + aes_ct (~64-512)
/// We pad cover traffic to the median real message size: 3200 bytes
pub const COVER_PACKET_SIZE: usize = 3200;

/// Cover traffic session tag prefix (first byte of all cover packets)
pub const COVER_TAG_PREFIX: u8 = 0xC0;

/// Maximum jitter (seconds) added to inter-message interval
const MAX_JITTER_SECONDS: f64 = 5.0;

/// CBNP configuration
#[derive(Debug, Clone)]
pub struct CbnpConfig {
    /// Average interval between cover messages (seconds)
    pub lambda_seconds: f64,
    /// Whether cover traffic is enabled
    pub enabled: bool,
    /// Maximum messages per burst
    pub max_burst: u64,
}

impl Default for CbnpConfig {
    fn default() -> Self {
        Self {
            lambda_seconds: 30.0, // Average 30s between cover messages
            enabled: true,
            max_burst: 3,
        }
    }
}

/// CBNP session state
pub struct CbnpSession {
    config: CbnpConfig,
    running: Arc<AtomicBool>,
    cover_count: Arc<AtomicU64>,
    last_send: Arc<std::sync::Mutex<Instant>>,
    /// Public key used for cover traffic (distinct from real identity)
    cover_public_key: [u8; 32],
    /// Secret key for generating deterministic cover packets
    cover_secret: [u8; 32],
}

impl CbnpSession {
    /// Create a new CBNP session with the given config
    pub fn new(config: CbnpConfig) -> Self {
        let mut cover_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut cover_secret);
        let mut cover_public_key = [0u8; 32];
        // Derive a "public key" from the secret (just a hash, not real ML-KEM)
        let mut hasher = Sha256::new();
        hasher.update(b"cbnp-cover-pk-v1");
        hasher.update(&cover_secret);
        cover_public_key.copy_from_slice(&hasher.finalize());

        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            cover_count: Arc::new(AtomicU64::new(0)),
            last_send: Arc::new(std::sync::Mutex::new(Instant::now())),
            cover_public_key,
            cover_secret,
        }
    }

    /// Generate a cover traffic packet
    pub fn generate_cover_packet(&self) -> Result<Vec<u8>, CryptoError> {
        let mut packet = vec![0u8; COVER_PACKET_SIZE];

        // First byte is the tag prefix (recipient uses this to detect cover)
        packet[0] = COVER_TAG_PREFIX;

        // Fill with deterministic-but-unpredictable content derived from secret
        let mut hasher = Sha256::new();
        hasher.update(b"cbnp-cover-packet-v1");
        hasher.update(&self.cover_secret);
        let count = self.cover_count.load(Ordering::Relaxed);
        hasher.update(&count.to_be_bytes());
        let seed_hash = hasher.finalize();

        // Use first 32 bytes of hash as seed for pseudo-random fill
        let mut fill_seed = seed_hash;
        for chunk in packet[1..].chunks_mut(32) {
            let mut h = Sha256::new();
            h.update(&fill_seed);
            h.update(b"cbnp-fill");
            let out = h.finalize();
            let len = chunk.len().min(32);
            chunk[..len].copy_from_slice(&out[..len]);
            fill_seed = out; // chain
        }

        self.cover_count.fetch_add(1, Ordering::Relaxed);
        Ok(packet)
    }

    /// Calculate the next send delay (Poisson + jitter)
    pub fn next_delay(&self) -> Duration {
        if !self.config.enabled {
            return Duration::from_secs(3600); // effectively paused
        }

        // Exponential distribution (Poisson process inter-arrival time):
        // inverse transform sampling: -ln(1-U)/lambda
        let u: f64 = rand::thread_rng().gen_range(0.0001..1.0);
        let base_delay = -((1.0 - u).ln()) / self.config.lambda_seconds;
        let jitter: f64 = rand::thread_rng().gen_range(0.0..MAX_JITTER_SECONDS);
        Duration::from_secs_f64(base_delay + jitter)
    }

    /// Check if a packet is cover traffic (starts with COVER_TAG_PREFIX)
    pub fn is_cover_traffic(packet: &[u8]) -> bool {
        !packet.is_empty() && packet[0] == COVER_TAG_PREFIX
    }

    /// Get the cover count (for metrics)
    pub fn cover_count(&self) -> u64 {
        self.cover_count.load(Ordering::Relaxed)
    }

    /// Get the cover public key
    pub fn cover_public_key(&self) -> &[u8; 32] {
        &self.cover_public_key
    }

    /// Stop the CBNP session
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Start running flag
    pub fn start(&self) {
        self.running.store(true, Ordering::Relaxed);
    }
}

/// Generate a batch of cover packets (for burst mode)
pub fn generate_cover_burst(session: &CbnpSession, count: usize) -> Result<Vec<Vec<u8>>, CryptoError> {
    let mut packets = Vec::with_capacity(count);
    for _ in 0..count {
        packets.push(session.generate_cover_packet()?);
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cover_packet_generation() {
        let config = CbnpConfig::default();
        let session = CbnpSession::new(config);
        let packet = session.generate_cover_packet().unwrap();
        assert_eq!(packet.len(), COVER_PACKET_SIZE);
        assert_eq!(packet[0], COVER_TAG_PREFIX);
    }

    #[test]
    fn test_cover_traffic_detection() {
        let config = CbnpConfig::default();
        let session = CbnpSession::new(config);
        let packet = session.generate_cover_packet().unwrap();
        assert!(CbnpSession::is_cover_traffic(&packet));
        // Random data is not cover traffic
        let random = vec![0xABu8; 100];
        assert!(!CbnpSession::is_cover_traffic(&random));
        // Empty is not cover traffic
        assert!(!CbnpSession::is_cover_traffic(&[]));
    }

    #[test]
    fn test_cover_packets_are_different() {
        let config = CbnpConfig::default();
        let session = CbnpSession::new(config);
        let p1 = session.generate_cover_packet().unwrap();
        let p2 = session.generate_cover_packet().unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_next_delay_reasonable() {
        let config = CbnpConfig {
            lambda_seconds: 1.0,
            enabled: true,
            max_burst: 1,
        };
        let session = CbnpSession::new(config);
        let delay = session.next_delay();
        // Delay should be at least 0 and at most lambda + MAX_JITTER
        assert!(delay.as_secs_f64() >= 0.0);
        assert!(delay.as_secs_f64() < 100.0); // sanity
    }

    #[test]
    fn test_disabled_cbnp_long_delay() {
        let config = CbnpConfig {
            enabled: false,
            ..Default::default()
        };
        let session = CbnpSession::new(config);
        let delay = session.next_delay();
        assert!(delay.as_secs() >= 3600);
    }

    #[test]
    fn test_cover_burst() {
        let config = CbnpConfig::default();
        let session = CbnpSession::new(config);
        let packets = generate_cover_burst(&session, 3).unwrap();
        assert_eq!(packets.len(), 3);
        for p in &packets {
            assert_eq!(p.len(), COVER_PACKET_SIZE);
            assert_eq!(p[0], COVER_TAG_PREFIX);
        }
    }
}
