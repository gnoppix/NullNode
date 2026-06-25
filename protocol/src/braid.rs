// -------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// -------------------------------------------------------------------------------
// NullNode ML-KEM-1024 SPQR Braid Protocol
//
// Implements chunk-based key exchange for large post-quantum keys (ML-KEM-1024).
// The braid protocol enables streaming key exchange to avoid latency spikes.
//
// ACS2.6 Part I.1 requirement: SPQR (Secure Parallelizable Quantum-Resistant) protocol.
// -------------------------------------------------------------------------------

use serde::{Deserialize, Serialize};

/// A chunk in the braid protocol exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BraidChunk {
    /// Chunk sequence number (0-indexed)
    pub chunk_num: u32,
    /// Total number of chunks in this exchange
    pub total_chunks: u32,
    /// SHA-512 hash of the encapsulation key (64 bytes)
    pub ek_hash: Vec<u8>,
    /// The seed extracted from the encapsulation key (32 bytes)
    pub seed: Vec<u8>,
    /// Chunk payload (partial key material)
    pub payload: Vec<u8>,
}

/// State machine for ML-KEM-1024 SPQR braid handshake.
#[derive(Debug)]
pub struct BraidHandshake {
    pub total_chunks: u32,
    pub received_chunks: Vec<BraidChunk>,
    pub ek_hash: Vec<u8>,
    pub complete: bool,
}

impl BraidHandshake {
    /// Create a new braid handshake for ML-KEM-1024 key exchange.
    /// ML-KEM-1024 public key = 1568 bytes, split into chunks of CHUNK_SIZE.
    pub fn new() -> Self {
        Self {
            total_chunks: 0,
            received_chunks: Vec::new(),
            ek_hash: vec![0u8; 64],
            complete: false,
        }
    }

    /// CHUNK_SIZE: 64 bytes per chunk (allows parallel processing)
    pub const CHUNK_SIZE: usize = 64;

    /// Add a received chunk and return true if handshake is complete.
    pub fn add_chunk(&mut self, chunk: BraidChunk) -> Result<bool, String> {
        // Validate chunk_num bounds
        if chunk.chunk_num >= chunk.total_chunks {
            return Err(format!(
                "chunk_num {} >= total_chunks {}",
                chunk.chunk_num, chunk.total_chunks
            ));
        }

        // Initialize ek_hash on first chunk
        if self.total_chunks == 0 {
            self.total_chunks = chunk.total_chunks;
            self.ek_hash.clone_from(&chunk.ek_hash);
        }

        // Verify ek_hash consistency
        if self.ek_hash != chunk.ek_hash {
            return Err("ek_hash mismatch".to_string());
        }

        // Check for duplicate
        for c in &self.received_chunks {
            if c.chunk_num == chunk.chunk_num {
                return Err("duplicate chunk".to_string());
            }
        }

        self.received_chunks.push(chunk);

        // Check if complete
        if self.received_chunks.len() == self.total_chunks as usize {
            self.complete = true;
        }

        Ok(self.complete)
    }

    /// Reconstruct the full encapsulation key from chunks.
    pub fn reconstruct_enc_key(&self) -> Vec<u8> {
        let mut key = vec![0u8; self.total_chunks as usize * Self::CHUNK_SIZE];
        for chunk in &self.received_chunks {
            let start = chunk.chunk_num as usize * Self::CHUNK_SIZE;
            let end = start + chunk.payload.len().min(Self::CHUNK_SIZE);
            if end <= key.len() {
                key[start..end].copy_from_slice(&chunk.payload[..end - start]);
            }
        }
        key
    }
}

impl Default for BraidHandshake {
    fn default() -> Self {
        Self::new()
    }
}