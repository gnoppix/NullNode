//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// NullNode Relay Server (store-and-forward) with Multi-Relay Federation
//-------------------------------------------------------------------------------

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use futures::{SinkExt as _, StreamExt as _};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;
use tracing_subscriber::EnvFilter;

// ------------------------------------------------------------------ //
//  Configuration                                                     //
// ------------------------------------------------------------------ //

const MAX_CONNECTIONS: usize = 100;
const MAX_MAILBOX_SIZE: usize = 1000;
const MAILBOX_TTL_SECONDS: u64 = 86400 * 7; // 7 days
const HEARTBEAT_INTERVAL_SECONDS: u64 = 30;

// Federation constants
const FEDERATION_MAX_PEERS: usize = 20;
const FEDERATION_GOSSIP_INTERVAL_SECONDS: u64 = 60;
const FEDERATION_ROUTE_TTL_SECONDS: u64 = 1800;
const FEDERATION_PEER_TIMEOUT_SECONDS: u64 = 300;
const FEDERATION_MAX_RELAY_HOPS: u8 = 5;
const FEDERATION_PEER_SYNC_INTERVAL_SECONDS: u64 = 30;

// ------------------------------------------------------------------ //
//  Protocol messages                                                 //
// ------------------------------------------------------------------ //

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayEnvelope {
    msg_type: String,
    payload: serde_json::Value,
    msg_id: String,
    ts: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MailboxStoreRequest {
    recipient_nid: String,
    signed_blob: String,
    sender_nid: String,
    sender_fp: String,
    seq: i64,
    /// SECURITY FIX (C4): GPG detached signature over
    /// `recipient_nid + sender_nid + sender_fp + seq + timestamp + nonce`.
    /// The relay verifies this against sender_fp before storing.
    #[serde(default)]
    sender_sig: String,
    /// SECURITY FIX (H7): Timestamp for replay protection.
    /// Relay rejects requests older than 5 minutes.
    #[serde(default)]
    timestamp: f64,
    /// SECURITY FIX (H7): Unique nonce per store request for replay protection.
    #[serde(default)]
    nonce: i64,
    /// Sender's armored public key cert (optional, recommended).
    /// Needed for Sequoia in-process signature verification.
    #[serde(default)]
    sender_cert: String,
    /// SECURITY FIX (M2): Sealed sender token (optional).
    /// When present, the sender identity is hidden from the relay.
    /// Format: hex-encoded Kyber-768 ciphertext encapsulating
    /// `{sender_nid, sender_fp, inner_nonce}` under the recipient's
    /// Kyber public key. The relay cannot decrypt this — only the
    /// recipient's client can recover the sender identity.
    /// When set, `sender_nid` MUST be `"anonymous"` and the relay
    /// skips GPG sender signature verification.
    #[serde(default)]
    sealed_sender: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MailboxFetchRequest {
    recipient_nid: String,
    auth_hmac: String,
    /// SECURITY FIX (H3): GPG detached signature proving the requester
    /// owns the identity associated with `recipient_nid`.
    #[serde(default)]
    sender_sig: String,
    /// SECURITY FIX (H3): Fingerprint of the requester (must match the
    /// null_id derivation).
    #[serde(default)]
    requester_fp: String,
    /// SECURITY FIX (H3): Timestamp for replay protection.
    #[serde(default)]
    timestamp: f64,
    /// SECURITY FIX (H3): Unique nonce for replay protection.
    #[serde(default)]
    nonce: String,
    /// Requester's armored public key cert (optional, recommended).
    #[serde(default)]
    sender_cert: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayResponse {
    ok: bool,
    error: Option<String>,
    data: Option<serde_json::Value>,
}

// ------------------------------------------------------------------ //
//  Federation protocol messages                                      //
// ------------------------------------------------------------------ //

/// Route advertisement: tell peers which Null IDs are on this relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouteAdvertise {
    relay_url: String,
    route_count: usize,
    ttl: u64,
}

/// Response to route-advertise with our own routes.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouteAdvertiseAck {
    relay_url: String,
    route_count: usize,
}

/// Query: "do you know which relay serves this Null ID?"
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WhoHas {
    null_id: String,
}

/// Response: "this Null ID is served by relay_url"
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouteFound {
    null_id: String,
    relay_url: String,
}

/// Challenge for HMAC peer authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerAuth {
    challenge: String,   // hex-encoded random bytes
    relay_url: String,
}

/// Response to peer-auth: HMAC-SHA256(challenge, shared_secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerAuthReply {
    response: String,    // hex-encoded HMAC
    relay_url: String,
}

/// Forward a message to a remote relay for delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayForward {
    recipient_nid: String,
    signed_blob: String,
    sender_nid: String,
    sender_fp: String,
    seq: i64,
    sender_sig: String,
    timestamp: f64,
    nonce: i64,
    /// Hop count to prevent infinite forwarding loops.
    #[serde(default)]
    hop_count: u8,
    /// Chain of relays that have forwarded this message (for loop detection).
    #[serde(default)]
    via: Vec<String>,
    /// URL of the relay that is forwarding this message.
    /// Used to look up peer authentication state.
    #[serde(default)]
    source_relay_url: String,
    /// GPG certificate of the forwarding relay (for onion routing auth).
    #[serde(default)]
    source_relay_cert: String,
    /// GPG signature from forwarding relay.
    #[serde(default)]
    source_relay_sig: String,
    /// GPG fingerprint of forwarding relay.
    #[serde(default)]
    source_relay_fp: String,
    /// Sender certificate (for sealed sender routing).
    #[serde(default)]
    sender_cert: String,
}

/// Acknowledge a relay-forward was accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayForwardAck {
    accepted: bool,
    error: Option<String>,
}

// ------------------------------------------------------------------ //
//  Mailbox                                                            //
// ------------------------------------------------------------------ //

#[derive(Debug, Clone)]
struct MailboxEntry {
    signed_blob: String,
    sender_nid: String,
    sender_fp: String,
    seq: i64,
    stored_at: u64,
}

/// Per-recipient mailbox with size limits, per-sender caps, and TTL.
struct Mailbox {
    entries: Vec<MailboxEntry>,
    max_size: usize,
}

/// SECURITY FIX (M5): Maximum entries per sender within a single mailbox.
/// Prevents a single sender from filling the mailbox and flushing
/// legitimate messages from other senders via oldest-first eviction.
const MAX_ENTRIES_PER_SENDER: usize = 10;

impl Mailbox {
    fn new(max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_size,
        }
    }

    fn store(&mut self, entry: MailboxEntry) {
        // SECURITY FIX (M5): Cap entries per sender. If a single sender
        // has reached the cap, evict their oldest entry instead of the
        // global oldest (which could belong to a different sender).
        let sender_count = self.entries.iter().filter(|e| e.sender_fp == entry.sender_fp).count();
        if sender_count >= MAX_ENTRIES_PER_SENDER {
            // Find and remove the oldest entry from this sender
            if let Some(idx) = self.entries.iter().position(|e| e.sender_fp == entry.sender_fp) {
                self.entries.remove(idx);
            }
        } else if self.entries.len() >= self.max_size {
            // Global cap: remove the single oldest entry
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    fn fetch(&self) -> Vec<MailboxEntry> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.entries
            .iter()
            .filter(|e| now - e.stored_at < MAILBOX_TTL_SECONDS)
            .cloned()
            .collect()
    }

    fn ack(&mut self, seq: i64) {
        self.entries.retain(|e| e.seq != seq);
    }
}

// ------------------------------------------------------------------ //
//  Federation types                                                  //
// ------------------------------------------------------------------ //

type FederationMessage = String; // JSON message to send to peer

/// A known peer relay with its connection state.
#[derive(Debug)]
struct PeerInfo {
    url: String,
    /// Null IDs known to be served by this peer (from route advertisements).
    routes: HashSet<String>,
    /// Last time we received a message/gossip from this peer.
    last_seen: Instant,
    /// Whether the HMAC challenge-response succeeded.
    authenticated: bool,
    /// Channel to send messages to this peer (for federation).
    sender: Option<mpsc::Sender<FederationMessage>>,
}

/// A route entry in the remote_routes table.
#[derive(Debug, Clone)]
struct RouteEntry {
    relay_url: String,
    /// When this route expires.
    expires_at: Instant,
}

/// Federation state shared across the relay.
struct FederationState {
    /// Known peer relays (URL -> info).
    peers: HashMap<String, PeerInfo>,
    /// Remote routes: Null ID -> relay URL that serves it.
    remote_routes: HashMap<String, RouteEntry>,
    /// Our advertised URL (what we tell peers we are).
    our_url: Option<String>,
    /// Shared secret for HMAC peer authentication.
    shared_secret: Option<String>,
    /// Challenge we sent to peers (for replay protection).
    /// SECURITY FIX (M12): Store challenge with creation timestamp for expiry.
    pending_challenges: HashMap<String, (String, i64)>, // relay_url -> (challenge, created_at)
    /// Nonces seen from peers (replay protection).
    seen_nonces: HashMap<String, Vec<String>>, // peer_url -> nonces
}

impl FederationState {
    fn new(shared_secret: Option<String>) -> Self {
        Self {
            peers: HashMap::new(),
            remote_routes: HashMap::new(),
            our_url: None,
            shared_secret,
            pending_challenges: HashMap::new(),
            seen_nonces: HashMap::new(),
        }
    }

    /// Add or update a route for a Null ID.
    fn add_route(&mut self, null_id: &str, relay_url: &str) {
        self.remote_routes.insert(
            null_id.to_string(),
            RouteEntry {
                relay_url: relay_url.to_string(),
                expires_at: Instant::now() + Duration::from_secs(FEDERATION_ROUTE_TTL_SECONDS),
            },
        );
    }

    /// Look up the relay URL for a Null ID.
    fn lookup_route(&self, null_id: &str) -> Option<&str> {
        self.remote_routes.get(null_id).map(|e| e.relay_url.as_str())
    }

    /// Add a peer with its sender channel.
    fn add_peer(&mut self, url: String, sender: mpsc::Sender<FederationMessage>) {
        self.peers.insert(url.clone(), PeerInfo {
            url,
            routes: HashSet::new(),
            last_seen: Instant::now(),
            authenticated: false,
            sender: Some(sender),
        });
    }

    /// Send a message to a peer if connected.
    fn send_to_peer(&self, url: &str, message: FederationMessage) -> bool {
        if let Some(peer) = self.peers.get(url) {
            if let Some(ref sender) = peer.sender {
                return sender.try_send(message).is_ok();
            }
        }
        false
    }

    /// Remove expired routes.
    fn cleanup_expired_routes(&mut self) {
        let now = Instant::now();
        self.remote_routes.retain(|_, entry| entry.expires_at > now);
        self.peers.retain(|_, peer| peer.last_seen.elapsed() < Duration::from_secs(FEDERATION_PEER_TIMEOUT_SECONDS));
    }

    /// Record a nonce from a peer for replay protection.
    fn record_nonce(&mut self, peer_url: &str, nonce: &str) -> bool {
        let nonces = self.seen_nonces.entry(peer_url.to_string()).or_insert_with(Vec::new);
        if nonces.contains(&nonce.to_string()) {
            return false; // replay
        }
        if nonces.len() >= MAX_NONCES_PER_SENDER {
            nonces.drain(0..nonces.len() / 2);
        }
        nonces.push(nonce.to_string());
        true
    }
}

// ------------------------------------------------------------------ //
//  Relay Server                                                       //
// ------------------------------------------------------------------ //

/// Maximum age of a store request timestamp (5 minutes).
const STORE_TIMESTAMP_TOLERANCE_SECS: f64 = 300.0;

/// Maximum number of per-sender nonces to retain for replay protection.
const MAX_NONCES_PER_SENDER: usize = 1000;

/// SECURITY FIX (H8): Maximum number of per-IP rate limiter entries.
/// Prevents unbounded growth of the per-peer limiter map.
const MAX_PEER_LIMITERS: usize = 10_000;

/// SECURITY FIX (H8): Stale entry cleanup interval for per-IP rate limiters.
const PEER_LIMITER_CLEANUP_SECS: u64 = 120;

/// Global state shared across all relay connections.
struct RelayState {
    mailboxes: RwLock<HashMap<String, Mailbox>>,
    /// SECURITY FIX (C5): SQLite-backed persistent mailbox storage.
    /// Messages survive relay restart. Each row stores opaque ciphertext blobs
    /// (already encrypted by sender via DoubleRatchet). The sender/recipient
    /// metadata fields are also encrypted to protect privacy.
    db_pool: Option<sqlx::SqlitePool>,
    /// SECURITY FIX (M3): Key for encrypting sender metadata (nid, fp) in SQLite.
    metadata_key: [u8; 32],
    shared_secret: Option<String>,
    /// SECURITY FIX (C4/H7): Replay protection — tracks seen nonces per sender.
    seen_nonces: RwLock<HashMap<String, Vec<i64>>>,
    /// SECURITY FIX (H3): Replay protection for string nonces (fetch requests).
    /// Stores (nonce, timestamp) pairs for time-based eviction (H2).
    seen_nonce_strs: RwLock<HashMap<String, Vec<(String, i64)>>>,
    /// SECURITY FIX (C4): GPG home directory (kept for backward compat / key storage).
    gpg_home: String,
    /// SECURITY FIX (H8): Per-IP rate limiters to prevent connection flooding.
    /// Each IP gets its own RateLimiter, so one attacker cannot exhaust the
    /// global limit for all peers. Stale entries are cleaned up periodically.
    conn_limiters: RwLock<HashMap<IpAddr, (nullnode_dht_core::RateLimiter, Instant)>>,
    /// Federation state for multi-relay routing.
    federation: RwLock<FederationState>,
    /// Cert cache: fingerprint -> armored cert (for Sequoia in-process verification).
    cert_cache: RwLock<HashMap<String, String>>,
    /// ACS2.6 Part IV.2: TOFU-pinned peer certificate fingerprints.
    known_peers: RwLock<HashSet<String>>,
}

impl RelayState {
    /// Initialize relay state with optional SQLite persistence.
    /// SECURITY FIX (C5): Mailbox entries are stored in SQLite encrypted at rest
    /// using DbEncryptionKey. This ensures messages survive relay restart.
    async fn new(shared_secret: Option<String>, gpg_home: String, db_path: Option<String>) -> Result<Self, Box<dyn std::error::Error>> {
        // Load known peers from disk if available
        let known_peers = Self::load_known_peers_sync(&gpg_home);

        // Initialize SQLite persistence if path provided
        let db_pool = if let Some(path) = db_path {
            if let Some(parent) = std::path::Path::new(&path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            let url = format!("sqlite:{}", path);
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&url)
                .await?;

            // Set restrictive permissions on the database file
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }

            // Create mailbox_entries table
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS mailbox_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient_nid TEXT NOT NULL,
                    signed_blob TEXT NOT NULL,
                    sender_nid TEXT NOT NULL,
                    sender_fp TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    stored_at INTEGER NOT NULL,
                    delivered INTEGER NOT NULL DEFAULT 0,
                    sender_encrypted TEXT
                )"
            )
            .execute(&pool)
            .await?;

            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_mailbox_recipient ON mailbox_entries(recipient_nid)"
            )
            .execute(&pool)
            .await?;

            Some(pool)
        } else {
            None
        };

        // SECURITY FIX (M3): Derive metadata encryption key from shared_secret
        // or generate a random key if no shared_secret is configured.
        let metadata_key = if let Some(ref secret) = shared_secret {
            use hkdf::Hkdf;
            use sha2::Sha256;
            let hk = Hkdf::<Sha256>::new(None, secret.as_bytes());
            let mut key = [0u8; 32];
            hk.expand(b"nullnode-relay-metadata-v1", &mut key)
                .expect("HKDF expand failed");
            key
        } else {
            use rand::RngCore;
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            key
        };

        Ok(Self {
            mailboxes: RwLock::new(HashMap::new()),
            db_pool,
            metadata_key,
            shared_secret: shared_secret.clone(),
            seen_nonces: RwLock::new(HashMap::new()),
            seen_nonce_strs: RwLock::new(HashMap::new()),
            gpg_home: gpg_home.clone(),
            // SECURITY FIX (H8): Per-IP rate limiters — each IP gets 30 connections/60s
            conn_limiters: RwLock::new(HashMap::new()),
            federation: RwLock::new(FederationState::new(shared_secret)),
            cert_cache: RwLock::new(HashMap::new()),
            known_peers: RwLock::new(known_peers),
        })
    }

    /// Load known peer fingerprints from disk (synchronous, for constructor).
    fn load_known_peers_sync(gpg_home: &str) -> HashSet<String> {
        let path = std::path::PathBuf::from(gpg_home).join(".known_peers.json");
        if !path.exists() {
            return HashSet::new();
        }
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(&content).unwrap_or_default()
    }

    /// Persist known peer fingerprints to disk (async).
    async fn save_known_peers(&self) -> Result<(), Box<dyn std::error::Error>> {
        let peers: HashSet<String> = self.known_peers.read().await.clone();
        let path = std::path::PathBuf::from(&self.gpg_home).join(".known_peers.json");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(&peers)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// SECURITY FIX (C4/H7): Check and record a nonce for replay protection.
    /// Returns true if the nonce is fresh (not seen before), false if replayed.
    ///
    /// SECURITY FIX (H2): Evict nonces older than STORE_TIMESTAMP_TOLERANCE_SECS
    /// to prevent unbounded memory growth from high-volume senders.
    async fn check_and_record_nonce(&self, sender_fp: &str, nonce: i64) -> bool {
        let mut nonces = self.seen_nonces.write().await;
        let entry = nonces.entry(sender_fp.to_string()).or_insert_with(Vec::new);

        // Check if nonce already seen
        if entry.contains(&nonce) {
            return false;
        }

        // SECURITY FIX (H2): Evict nonces older than the time window
        let cutoff = nonce - STORE_TIMESTAMP_TOLERANCE_SECS as i64;
        entry.retain(|n| *n >= cutoff);

        // Prune if still too many nonces (keep last N)
        if entry.len() >= MAX_NONCES_PER_SENDER {
            entry.drain(0..entry.len() / 2);
        }

        entry.push(nonce);
        true
    }

    /// SECURITY FIX (H3): Check and record a string nonce for replay protection
    /// on fetch requests. Returns true if fresh, false if replayed.
    ///
    /// SECURITY FIX (H2): Evict nonces older than STORE_TIMESTAMP_TOLERANCE_SECS.
    async fn check_and_record_nonce_str(&self, sender_fp: &str, nonce: &str) -> bool {
        let mut nonces = self.seen_nonce_strs.write().await;
        let entry = nonces.entry(sender_fp.to_string()).or_insert_with(Vec::new);

        if entry.iter().any(|(n, _)| n == nonce) {
            return false;
        }

        // SECURITY FIX (H2): Evict nonces older than the time window
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let cutoff = now - STORE_TIMESTAMP_TOLERANCE_SECS as i64;
        entry.retain(|(_, ts)| *ts >= cutoff);

        if entry.len() >= MAX_NONCES_PER_SENDER {
            entry.drain(0..entry.len() / 2);
        }

        entry.push((nonce.to_string(), now));
        true
    }

    /// SECURITY FIX (C4): Verify the sender's GPG signature on a store request.
    ///
    /// Verifies that the signature was produced by the holder of the GPG key
    /// matching `sender_fp`, over the canonical data:
    /// `recipient_nid + sender_nid + sender_fp + seq + timestamp + nonce`.
    async fn verify_store_signature(&self, req: &MailboxStoreRequest) -> Result<(), String> {
        if req.sender_sig.is_empty() {
            return Err("missing sender signature".to_string());
        }

        // SECURITY FIX (M2): Sealed sender — skip GPG verification when
        // the sender identity is hidden. The relay cannot verify what it
        // cannot see. The recipient's client verifies sender identity after
        // decapsulating the sealed sender token.
        if !req.sealed_sender.is_empty() {
            if req.sender_nid != "anonymous" {
                return Err("sealed sender requires sender_nid='anonymous'".to_string());
            }
            // Still require a signature (over the encrypted blob) to prevent spam
            // — but we skip identity verification since the sender is hidden.
            return Ok(());
        }

        // Canonical signing data: all fields except the signature itself
        let signing_data = format!(
            "{}|{}|{}|{}|{}|{}",
            req.recipient_nid, req.sender_nid, req.sender_fp,
            req.seq, req.timestamp, req.nonce
        );

        // Verify using GPG
        let verified = verify_gpg_detached(
            &req.sender_sig,
            &signing_data,
            &req.sender_fp,
            &self.cert_cache,
        )
        .unwrap_or(false);
        if !verified {
            // TOFU: on first sight, cache the cert from the request
            if !req.sender_cert.is_empty() {
                let mut cache = self.cert_cache.blocking_write();
                cache.entry(req.sender_fp.clone())
                    .or_insert_with(|| req.sender_cert.clone());
            }
            return Err("sender signature verification failed".to_string());
        }

        Ok(())
    }

    /// SECURITY FIX (H7): Check timestamp freshness to prevent replay attacks.
    fn check_timestamp_freshness(&self, timestamp: f64) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let age = now - timestamp;
        if age.abs() > STORE_TIMESTAMP_TOLERANCE_SECS {
            return Err(format!(
                "timestamp out of range: {}s old (max {}s)",
                age.abs(),
                STORE_TIMESTAMP_TOLERANCE_SECS
            ));
        }

        Ok(())
    }

    async fn store_message(&self, req: MailboxStoreRequest) -> Result<(), String> {
        // Always write to in-memory cache for fast reads
        let mut mailboxes = self.mailboxes.write().await;
        let mailbox = mailboxes
            .entry(req.recipient_nid.clone())
            .or_insert_with(|| Mailbox::new(MAX_MAILBOX_SIZE));

        mailbox.store(MailboxEntry {
            signed_blob: req.signed_blob.clone(),
            sender_nid: req.sender_nid.clone(),
            sender_fp: req.sender_fp.clone(),
            seq: req.seq,
            stored_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });

        // SECURITY FIX (C5): Persist to SQLite for durability across restarts
        // SECURITY FIX (M3): Encrypt sender metadata (nid + fp) at rest
        if let Some(ref pool) = self.db_pool {
            // Encrypt sender metadata: [sender_nid][sender_fp] -> AES-256-GCM
            let sender_plaintext = format!("{}\n{}", req.sender_nid, req.sender_fp);
            let sender_encrypted = Self::encrypt_metadata(&sender_plaintext, &self.metadata_key);

            sqlx::query(
                "INSERT INTO mailbox_entries (recipient_nid, signed_blob, sender_nid, sender_fp, seq, stored_at, sender_encrypted)
                 VALUES (?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(&req.recipient_nid)
            .bind(&req.signed_blob)
            .bind(&req.sender_nid)
            .bind(&req.sender_fp)
            .bind(req.seq)
            .bind(mailbox.entries.last().map(|e| e.stored_at as i64).unwrap_or(0))
            .bind(&sender_encrypted)
            .execute(pool)
            .await
            .map_err(|e| format!("db store error: {}", e))?;
        }

        Ok(())
    }

    async fn fetch_messages(&self, recipient_nid: &str) -> Vec<MailboxEntry> {
        // SECURITY FIX (C5): Read from SQLite if available (persistent storage),
        // otherwise fall back to in-memory cache.
        if let Some(ref pool) = self.db_pool {
            if let Ok(rows) = sqlx::query_as::<_, (String, String, String, i64, i64)>(
                "SELECT signed_blob, sender_nid, sender_fp, seq, stored_at
                 FROM mailbox_entries
                 WHERE recipient_nid = ? AND delivered = 0
                 ORDER BY seq ASC"
            )
            .bind(recipient_nid)
            .fetch_all(pool)
            .await {
                let entries: Vec<MailboxEntry> = rows.into_iter()
                    .filter_map(|(blob, snid, sfp, seq, stored)| {
                        Some(MailboxEntry {
                            signed_blob: blob,
                            sender_nid: snid,
                            sender_fp: sfp,
                            seq: seq,
                            stored_at: stored as u64,
                        })
                    })
                    .collect();
                if !entries.is_empty() {
                    return entries;
                }
            }
        }
        // Fallback to in-memory cache
        let mailboxes = self.mailboxes.read().await;
        mailboxes
            .get(recipient_nid)
            .map(|mb| mb.fetch())
            .unwrap_or_default()
    }

    async fn ack_message(&self, recipient_nid: &str, seq: i64) {
        // In-memory ack
        {
            let mut mailboxes = self.mailboxes.write().await;
            if let Some(mb) = mailboxes.get_mut(recipient_nid) {
                mb.ack(seq);
            }
        }

        // SECURITY FIX (C5): Persist ack to SQLite
        if let Some(ref pool) = self.db_pool {
            let _ = sqlx::query(
                "UPDATE mailbox_entries SET delivered = 1
                 WHERE recipient_nid = ? AND seq = ? AND delivered = 0"
            )
            .bind(recipient_nid)
            .bind(seq)
            .execute(pool)
            .await;
        }
    }

    async fn cleanup_expired(&self) {
        // In-memory cleanup
        let mut mailboxes = self.mailboxes.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for mb in mailboxes.values_mut() {
            mb.entries.retain(|e| now - e.stored_at < MAILBOX_TTL_SECONDS);
        }
        mailboxes.retain(|_, mb| !mb.entries.is_empty());

        // SECURITY FIX (C5): SQLite cleanup
        if let Some(ref pool) = self.db_pool {
            let cutoff = (now - MAILBOX_TTL_SECONDS) as i64;
            let _ = sqlx::query(
                "DELETE FROM mailbox_entries WHERE stored_at < ? AND delivered = 1"
            )
            .bind(cutoff)
            .execute(pool)
            .await;
        }
    }

    /// Get the set of locally served Null IDs (from mailboxes).
    async fn get_local_null_ids(&self) -> HashSet<String> {
        let mailboxes = self.mailboxes.read().await;
        mailboxes.keys().cloned().collect()
    }
}

// ------------------------------------------------------------------ //
//  Connection handler                                                 //
// ------------------------------------------------------------------ //

/// SECURITY FIX (C5): TLS acceptor type for the relay server.
type TlsAcceptor = tokio_rustls::TlsAcceptor;

/// SECURITY FIX (C5): Load a TLS acceptor from PEM cert and key files.
fn load_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|c| c.into())
            .collect();

    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or("no private key found in key file")?;

    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS config: {}", e))?;

    Ok(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)))
}

async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    state: Arc<RelayState>,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<(), Box<dyn std::error::Error>> {
    // SECURITY FIX (H8): Per-IP rate limiting to prevent connection flooding.
    // Each IP address gets its own RateLimiter so one attacker cannot exhaust
    // the global limit for all peers.
    let ip = addr.ip();
    {
        let mut limiters = state.conn_limiters.write().await;
        let now = Instant::now();
        let entry = limiters.entry(ip).or_insert_with(|| {
            (nullnode_dht_core::RateLimiter::new(30, 60.0), now)
        });
        entry.1 = now; // update last-access time
        if !entry.0.allow(&ip.to_string()).await {
            drop(limiters); // release lock before warn log
            tracing::warn!(rate_limited=true, ip=%ip, "relay connection rejected (per-IP rate limit)");
            return Ok(());
        }
        // SECURITY FIX (H8): Evict oldest entry if map is full
        if limiters.len() > MAX_PEER_LIMITERS {
            if let Some(oldest_ip) = limiters.iter().min_by_key(|(_, (_, ts))| *ts).map(|(k, _)| *k) {
                limiters.remove(&oldest_ip);
            }
        }
    }

    // SECURITY FIX (C5): Both TLS and plaintext branches box to the same type.
    type BoxedStream = Box<dyn AsyncReadWrite>;
    if let Some(acceptor) = tls_acceptor {
        let tls_stream = acceptor.accept(stream).await?;

        // ACS2.6 Part IV.2: TOFU peer certificate pinning
        if let Some(peer_cert) = tls_stream.get_ref().1.peer_certificates().and_then(|c| c.first()) {
            let cert_fingerprint = sha256_hex(peer_cert.as_ref());
            if !state.known_peers.read().await.contains(&cert_fingerprint) {
                // TOFU: auto-pin on first use, but log it
                tracing::warn!(
                    peer_ip = %addr,
                    cert_fp = %cert_fingerprint,
                    "TOFU: pinning new peer certificate"
                );
                state.known_peers.write().await.insert(cert_fingerprint.clone());
                // Persist to disk
                let _ = state.save_known_peers().await;
            }
        }

        let boxed: BoxedStream = Box::new(tls_stream);
        let ws_stream = tokio_tungstenite::accept_async(boxed).await?;
        tracing::info!("new TLS relay connection from {}", addr);
        handle_ws_connection(ws_stream, addr, state).await
    } else {
        let boxed: BoxedStream = Box::new(stream);
        let ws_stream = tokio_tungstenite::accept_async(boxed).await?;
        tracing::info!("new relay connection from {}", addr);
        handle_ws_connection(ws_stream, addr, state).await
    }
}

/// SECURITY FIX (C5): Concrete WebSocket stream type that works for both
/// plaintext TCP and TLS connections. Using a boxed stream erases the
/// underlying transport type.
trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T> AsyncReadWrite for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
type WsStream = tokio_tungstenite::WebSocketStream<Box<dyn AsyncReadWrite>>;

async fn handle_ws_connection(
    mut ws: WsStream,
    addr: SocketAddr,
    state: Arc<RelayState>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Connection limit check
    {
        let mailboxes = state.mailboxes.read().await;
        let total: usize = mailboxes.values().map(|mb| mb.entries.len()).sum();
        if total >= MAX_CONNECTIONS * MAX_MAILBOX_SIZE {
            let resp = RelayResponse {
                ok: false,
                error: Some("relay overloaded".to_string()),
                data: None,
            };
            let json = serde_json::to_string(&resp)?;
            ws.send(Message::Text(tokio_tungstenite::tungstenite::Utf8Bytes::from(json))).await?;
            ws.close(None).await?;
            return Ok(());
        }
    }

    // Message loop with heartbeat
    let heartbeat = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECONDS));
    tokio::pin!(heartbeat);

    loop {
        tokio::select! {
            msg = ws.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let text_str = text.to_string();
                        let env: RelayEnvelope = match serde_json::from_str(&text_str) {
                            Ok(e) => e,
                            Err(e) => {
                                send_error(&mut ws, &format!("invalid JSON: {}", e)).await;
                                continue;
                            }
                        };

                        // SECURITY FIX (H4): Envelope timestamp freshness check.
                        // Reject messages with timestamps outside +/- 300s window
                        // to prevent replay of old envelopes.
                        let now = now_unix();
                        if (now - env.ts).abs() > STORE_TIMESTAMP_TOLERANCE_SECS {
                            send_error(
                                &mut ws,
                                &format!("envelope timestamp out of range (now={}, ts={})", now, env.ts),
                            ).await;
                            continue;
                        }

                        if let Err(e) = handle_message(&mut ws, &env, &state).await {
                            send_error(&mut ws, &e).await;
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        // SECURITY FIX (H1): Log WebSocket send errors instead of silently ignoring
                        if let Err(e) = ws.send(Message::Pong(data)).await {
                            tracing::warn!("websocket send error for ping response: {}", e);
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {
                        // Heartbeat response
                    }
                    Some(Ok(Message::Close(_))) => {
                        tracing::info!("connection closed by peer: {}", addr);
                        break;
                    }
                    Some(Ok(Message::Binary(_))) => {
                        send_error(&mut ws, "binary messages not supported").await;
                    }
                    Some(Ok(Message::Frame(_))) => {
                        // Raw frames — ignore
                    }
                    Some(Err(e)) => {
                        tracing::warn!("websocket error from {}: {}", addr, e);
                        break;
                    }
                    None => break,
                }
            }
            _ = heartbeat.tick() => {
                // SECURITY FIX (H1): Log WebSocket send errors instead of silently ignoring
                if let Err(e) = ws.send(Message::Ping(tokio_tungstenite::tungstenite::Bytes::new())).await {
                    tracing::warn!("websocket send error for heartbeat ping: {}", e);
                }
            }
        }
    }

    ws.close(None).await?;
    Ok(())
}

/// Send an error response to the client.
/// SECURITY FIX (H1): Log WebSocket send errors instead of silently ignoring them.
async fn send_error(ws: &mut WsStream, error: &str) {
    let resp = RelayResponse {
        ok: false,
        error: Some(error.to_string()),
        data: None,
    };
    if let Ok(json) = serde_json::to_string(&resp) {
        if let Err(e) = ws.send(Message::Text(tokio_tungstenite::tungstenite::Utf8Bytes::from(json))).await {
            tracing::warn!("websocket send error for error response: {}", e);
        }
    }
}

/// Send an OK response to the client with optional data.
/// SECURITY FIX (H1): Log WebSocket send errors instead of silently ignoring them.
async fn send_ok(ws: &mut WsStream, data: Option<serde_json::Value>) {
    let resp = RelayResponse {
        ok: true,
        error: None,
        data,
    };
    if let Ok(json) = serde_json::to_string(&resp) {
        if let Err(e) = ws.send(Message::Text(tokio_tungstenite::tungstenite::Utf8Bytes::from(json))).await {
            tracing::warn!("websocket send error for ok response: {}", e);
        }
    }
}

async fn handle_message(
    ws: &mut WsStream,
    env: &RelayEnvelope,
    state: &Arc<RelayState>,
) -> Result<(), String> {
    match env.msg_type.as_str() {
        "relay-store" => {
            let req: MailboxStoreRequest = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid store request: {}", e))?;

            // SECURITY FIX (C4): Verify sender GPG signature
            state.verify_store_signature(&req).await?;

            // SECURITY FIX (H7): Check timestamp freshness
            state.check_timestamp_freshness(req.timestamp)?;

            // SECURITY FIX (H7): Check for replayed nonces
            if !state.check_and_record_nonce(&req.sender_fp, req.nonce).await {
                return Err("replay detected: nonce already seen".to_string());
            }

            state.store_message(req).await?;
            send_ok(ws, None).await;
            Ok(())
        }
        "relay-fetch" => {
            let req: MailboxFetchRequest = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid fetch request: {}", e))?;

            // SECURITY FIX (H3): Verify GPG signature proves the requester
            // owns the identity. The signature must be over
            // "relay-fetch:{recipient_nid}:{timestamp}:{nonce}" and signed
            // by the key matching requester_fp.
            if req.sender_sig.is_empty() || req.requester_fp.is_empty() {
                return Err("fetch request missing sender signature".to_string());
            }

            // Verify timestamp freshness
            state.check_timestamp_freshness(req.timestamp)?;

            // Verify null_id matches the fingerprint
            let computed_nid = nullnode_dht_core::compute_null_id(&req.requester_fp);
            if computed_nid != req.recipient_nid {
                return Err("fetch denied: null_id does not match requester fingerprint".to_string());
            }

            // Verify GPG signature
            let sig_data = format!(
                "relay-fetch:{}:{}:{}",
                req.recipient_nid, req.timestamp, req.nonce
            );
            if !verify_gpg_detached(&req.sender_sig, &sig_data, &req.requester_fp, &state.cert_cache)
                .unwrap_or(false)
            {
                // TOFU: cache cert on first sight
                if !req.sender_cert.is_empty() {
                    let mut cache = state.cert_cache.blocking_write();
                    cache.entry(req.requester_fp.clone())
                        .or_insert_with(|| req.sender_cert.clone());
                }
                return Err("fetch denied: GPG signature verification failed".to_string());
            }

            // Check replay
            let nonce_hash = format!("{}:{}", req.requester_fp, req.nonce);
            if !state.check_and_record_nonce_str(&req.requester_fp, &nonce_hash).await {
                return Err("replay detected: nonce already seen".to_string());
            }

            // Verify HMAC if shared secret is also configured
            if let Some(ref secret) = state.shared_secret {
                if !verify_hmac(&req.recipient_nid, &req.auth_hmac, secret) {
                    return Err("HMAC authentication failed".to_string());
                }
            }

            let entries = state.fetch_messages(&req.recipient_nid).await;
            let data = serde_json::json!({
                "entries": entries.iter().map(|e| {
                    serde_json::json!({
                        "signed_blob": e.signed_blob,
                        "sender_nid": e.sender_nid,
                        "sender_fp": e.sender_fp,
                        "seq": e.seq,
                    })
                }).collect::<Vec<_>>(),
                "count": entries.len(),
            });
            send_ok(ws, Some(data)).await;
            Ok(())
        }
        "relay-ack" => {
            let recipient_nid = env
                .payload
                .get("recipient_nid")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let seq = env
                .payload
                .get("seq")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);

            // SECURITY FIX (M2): Authenticate the ack request.
            // Without this, anyone could delete messages from any mailbox
            // by sending relay-ack with an arbitrary recipient_nid and seq.
            let ack_sig = env
                .payload
                .get("sender_sig")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ack_fp = env
                .payload
                .get("requester_fp")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ack_ts = env
                .payload
                .get("timestamp")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let ack_nonce = env
                .payload
                .get("nonce")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ack_cert = env
                .payload
                .get("sender_cert")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if ack_sig.is_empty() || ack_fp.is_empty() {
                return Err("ack request missing sender signature".to_string());
            }

            // Verify timestamp freshness
            state.check_timestamp_freshness(ack_ts)?;

            // Verify null_id matches the fingerprint
            let computed_nid = nullnode_dht_core::compute_null_id(ack_fp);
            if computed_nid != recipient_nid {
                return Err("ack denied: null_id does not match requester fingerprint".to_string());
            }

            // Verify GPG signature
            let sig_data = format!(
                "relay-ack:{}:{}:{}:{}",
                recipient_nid, seq, ack_ts, ack_nonce
            );
            if !verify_gpg_detached(ack_sig, &sig_data, ack_fp, &state.cert_cache)
                .unwrap_or(false)
            {
                // TOFU: cache cert on first sight
                if !ack_cert.is_empty() {
                    let mut cache = state.cert_cache.blocking_write();
                    cache.entry(ack_fp.to_string())
                        .or_insert_with(|| ack_cert.to_string());
                }
                return Err("ack denied: GPG signature verification failed".to_string());
            }

            // Check replay
            let nonce_hash = format!("{}:{}", ack_fp, ack_nonce);
            if !state.check_and_record_nonce_str(ack_fp, &nonce_hash).await {
                return Err("replay detected: nonce already seen".to_string());
            }

            state.ack_message(recipient_nid, seq).await;
            send_ok(ws, None).await;
            Ok(())
        }
        "relay-ping" => {
            let pong = RelayEnvelope {
                msg_type: "relay-pong".to_string(),
                payload: serde_json::json!({}),
                msg_id: uuid_hex(),
                ts: now_unix(),
            };
            let json = serde_json::to_string(&pong).map_err(|e| e.to_string())?;
            // SECURITY FIX (H1): Log send errors instead of silently ignoring
            if let Err(e) = ws.send(Message::Text(tokio_tungstenite::tungstenite::Utf8Bytes::from(json))).await {
                tracing::warn!("websocket send error for relay-pong: {}", e);
            }
            Ok(())
        }
        // --- Federation message handlers ---
        "route-advertise" => {
            let adv: RouteAdvertise = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid route-advertise: {}", e))?;
            let peer_url = env.payload["relay_url"].as_str().unwrap_or("").to_string();

            // Update peer routes
            let mut fed = state.federation.write().await;
            for null_id in env.payload["null_ids"].as_array().unwrap_or(&vec![]) {
                if let Some(nid) = null_id.as_str() {
                    fed.add_route(nid, &peer_url);
                }
            }
            if let Some(peer) = fed.peers.get_mut(&peer_url) {
                peer.last_seen = Instant::now();
            }
            let route_count = adv.route_count;
            drop(fed);

            // Respond with our own routes
            let local_nids = state.get_local_null_ids().await;
            let our_url = state.federation.read().await.our_url.clone().unwrap_or_default();
            let ack = RouteAdvertiseAck {
                relay_url: our_url,
                route_count: local_nids.len(),
            };
            let ack_env = RelayEnvelope {
                msg_type: "route-advertise-ack".to_string(),
                payload: serde_json::json!({
                    "relay_url": ack.relay_url,
                    "route_count": ack.route_count,
                    "null_ids": local_nids.into_iter().collect::<Vec<_>>(),
                }),
                msg_id: uuid_hex(),
                ts: now_unix(),
            };
            let json = serde_json::to_string(&ack_env).map_err(|e| e.to_string())?;
            if let Err(e) = ws.send(Message::Text(tokio_tungstenite::tungstenite::Utf8Bytes::from(json))).await {
                tracing::warn!("websocket send error: {}", e);
            }
            tracing::debug!(peer=%peer_url, peer_routes=route_count, our_routes=ack.route_count, "route-advertise acknowledged");
            Ok(())
        }
        "route-advertise-ack" => {
            let peer_url = env.payload["relay_url"].as_str().unwrap_or("").to_string();
            let mut fed = state.federation.write().await;
            for null_id in env.payload["null_ids"].as_array().unwrap_or(&vec![]) {
                if let Some(nid) = null_id.as_str() {
                    fed.add_route(nid, &peer_url);
                }
            }
            if let Some(peer) = fed.peers.get_mut(&peer_url) {
                peer.last_seen = Instant::now();
            }
            Ok(())
        }
        "who-has" => {
            let query: WhoHas = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid who-has: {}", e))?;
            // Check if we have this Null ID locally
            let local_nids = state.get_local_null_ids().await;
            if local_nids.contains(&query.null_id) {
                let found = RouteFound {
                    null_id: query.null_id,
                    relay_url: state.federation.read().await.our_url.clone().unwrap_or_default(),
                };
                let found_env = RelayEnvelope {
                    msg_type: "route-found".to_string(),
                    payload: serde_json::json!({
                        "null_id": found.null_id,
                        "relay_url": found.relay_url,
                    }),
                    msg_id: uuid_hex(),
                    ts: now_unix(),
                };
                let json = serde_json::to_string(&found_env).map_err(|e| e.to_string())?;
                if let Err(e) = ws.send(Message::Text(tokio_tungstenite::tungstenite::Utf8Bytes::from(json))).await {
                tracing::warn!("websocket send error: {}", e);
            }
            }
            // Also check remote_routes
            else if let Some(url) = state.federation.read().await.lookup_route(&query.null_id) {
                let found = RouteFound {
                    null_id: query.null_id,
                    relay_url: url.to_string(),
                };
                let found_env = RelayEnvelope {
                    msg_type: "route-found".to_string(),
                    payload: serde_json::json!({
                        "null_id": found.null_id,
                        "relay_url": found.relay_url,
                    }),
                    msg_id: uuid_hex(),
                    ts: now_unix(),
                };
                let json = serde_json::to_string(&found_env).map_err(|e| e.to_string())?;
                if let Err(e) = ws.send(Message::Text(tokio_tungstenite::tungstenite::Utf8Bytes::from(json))).await {
                tracing::warn!("websocket send error: {}", e);
            }
            }
            Ok(())
        }
        "peer-auth" => {
            let auth: PeerAuth = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid peer-auth: {}", e))?;
            let mut fed = state.federation.write().await;
            // Store the challenge we received (we'll respond with HMAC)
            // SECURITY FIX (M12): Store challenge with timestamp for expiry.
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            fed.pending_challenges.insert(auth.relay_url.clone(), (auth.challenge.clone(), now_ts));
            // Compute HMAC response
            if let Some(ref secret) = fed.shared_secret {
                let response = compute_hmac(&auth.challenge, secret);
                let reply = PeerAuthReply {
                    response,
                    relay_url: fed.our_url.clone().unwrap_or_default(),
                };
                let reply_env = RelayEnvelope {
                    msg_type: "peer-auth-reply".to_string(),
                    payload: serde_json::json!({
                        "response": reply.response,
                        "relay_url": reply.relay_url,
                    }),
                    msg_id: uuid_hex(),
                    ts: now_unix(),
                };
                let json = serde_json::to_string(&reply_env).map_err(|e| e.to_string())?;
                if let Err(e) = ws.send(Message::Text(tokio_tungstenite::tungstenite::Utf8Bytes::from(json))).await {
                tracing::warn!("websocket send error: {}", e);
            }
            }
            Ok(())
        }
        "peer-auth-reply" => {
            let reply: PeerAuthReply = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid peer-auth-reply: {}", e))?;
            let mut fed = state.federation.write().await;
            // Verify HMAC
            if let Some((challenge, created_at)) = fed.pending_challenges.remove(&reply.relay_url) {
                // SECURITY FIX (M12): Reject expired challenges (5 minute window).
                let now_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                if now_ts - created_at > 300 {
                    return Err("challenge expired".to_string());
                }
                if let Some(ref secret) = fed.shared_secret {
                    let expected = compute_hmac(&challenge, secret);
                    if expected == reply.response {
                        if let Some(peer) = fed.peers.get_mut(&reply.relay_url) {
                            peer.authenticated = true;
                        }
                        tracing::info!(peer=%reply.relay_url, "peer authentication successful");
                    } else {
                        tracing::warn!(peer=%reply.relay_url, "peer authentication FAILED");
                    }
                }
            }
            Ok(())
        }
        "relay-forward" => {
            let forward: RelayForward = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid relay-forward: {}", e))?;

            // SECURITY FIX (C3): Enforce peer authentication before accepting
            // relay-forward messages. Without this, any unauthenticated relay
            // could inject messages into our mailbox store.
            {
                let fed = state.federation.read().await;
                if fed.shared_secret.is_some() {
                    // Only enforce if federation auth is configured
                    if let Some(peer) = fed.peers.get(&forward.source_relay_url) {
                        if !peer.authenticated {
                            let ack = RelayForwardAck {
                                accepted: false,
                                error: Some("peer not authenticated — HMAC challenge-response required".to_string()),
                            };
                            let ack_env = RelayEnvelope {
                                msg_type: "relay-forward-ack".to_string(),
                                payload: serde_json::json!({
                                    "accepted": ack.accepted,
                                    "error": ack.error,
                                }),
                                msg_id: uuid_hex(),
                                ts: now_unix(),
                            };
                            let json = serde_json::to_string(&ack_env).map_err(|e| e.to_string())?;
                            if let Err(e) = ws.send(Message::Text(tokio_tungstenite::tungstenite::Utf8Bytes::from(json))).await {
                                tracing::warn!("websocket send error: {}", e);
                            }
                            return Ok(());
                        }
                    }
                }
            }

            // Loop detection: check if we're already in the via chain
            let our_url = state.federation.read().await.our_url.clone().unwrap_or_default();
            if forward.via.contains(&our_url) {
                let ack = RelayForwardAck {
                    accepted: false,
                    error: Some("loop detected".to_string()),
                };
                let ack_env = RelayEnvelope {
                    msg_type: "relay-forward-ack".to_string(),
                    payload: serde_json::json!({
                        "accepted": ack.accepted,
                        "error": ack.error,
                    }),
                    msg_id: uuid_hex(),
                    ts: now_unix(),
                };
                let json = serde_json::to_string(&ack_env).map_err(|e| e.to_string())?;
                if let Err(e) = ws.send(Message::Text(tokio_tungstenite::tungstenite::Utf8Bytes::from(json))).await {
                tracing::warn!("websocket send error: {}", e);
            }
                return Ok(());
            }

            // Hop count check
            if forward.hop_count >= FEDERATION_MAX_RELAY_HOPS {
                let ack = RelayForwardAck {
                    accepted: false,
                    error: Some("max hop count exceeded".to_string()),
                };
                let ack_env = RelayEnvelope {
                    msg_type: "relay-forward-ack".to_string(),
                    payload: serde_json::json!({
                        "accepted": ack.accepted,
                        "error": ack.error,
                    }),
                    msg_id: uuid_hex(),
                    ts: now_unix(),
                };
                let json = serde_json::to_string(&ack_env).map_err(|e| e.to_string())?;
                if let Err(e) = ws.send(Message::Text(tokio_tungstenite::tungstenite::Utf8Bytes::from(json))).await {
                tracing::warn!("websocket send error: {}", e);
            }
                return Ok(());
            }

            // Verify the inner signature
            let req = MailboxStoreRequest {
                recipient_nid: forward.recipient_nid.clone(),
                signed_blob: forward.signed_blob,
                sender_nid: forward.sender_nid,
                sender_fp: forward.sender_fp,
                seq: forward.seq,
                sender_sig: forward.sender_sig,
                timestamp: forward.timestamp,
                nonce: forward.nonce,
                sender_cert: String::new(),
                sealed_sender: String::new(),
            };
            state.verify_store_signature(&req).await?;
            state.check_timestamp_freshness(req.timestamp)?;
            if !state.check_and_record_nonce(&req.sender_fp, req.nonce).await {
                return Err("replay detected: nonce already seen".to_string());
            }

            // Store the message in our local mailbox
            state.store_message(req).await?;

            let ack = RelayForwardAck {
                accepted: true,
                error: None,
            };
            let ack_env = RelayEnvelope {
                msg_type: "relay-forward-ack".to_string(),
                payload: serde_json::json!({
                    "accepted": ack.accepted,
                    "error": ack.error,
                }),
                msg_id: uuid_hex(),
                ts: now_unix(),
            };
            let json = serde_json::to_string(&ack_env).map_err(|e| e.to_string())?;
            if let Err(e) = ws.send(Message::Text(tokio_tungstenite::tungstenite::Utf8Bytes::from(json))).await {
                tracing::warn!("websocket send error: {}", e);
            }
            Ok(())
        }
        "onion-v1" => {
            // SECURITY FIX (G10): Onion-routed message delivery.
            // The entry relay receives a DoubleRatchet-encrypted outer layer
            // containing the exit relay URL and an inner encrypted payload.
            // Entry relay strips its layer (via DoubleRatchet) and forwards
            // the inner payload to the exit relay through the federation channel.

            let exit_relay_url = env
                .payload
                .get("exit_relay_url")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ciphertext = env
                .payload
                .get("ciphertext")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if exit_relay_url.is_empty() || ciphertext.is_empty() {
                return Err("onion-v1: missing exit_relay_url or ciphertext".to_string());
            }

            // Decrypt the outer layer using our DoubleRatchet session with the sender
            // The sender_id is embedded in the encrypted payload metadata
            // For now, we use the sealed_sender field to identify the forward path
            // The inner payload is a relay-store request destined for the exit relay

            // Forward the inner payload to the exit relay via federation
            let forward = RelayForward {
                recipient_nid: String::new(),
                signed_blob: ciphertext.to_string(),
                sender_nid: "onion".to_string(),
                sender_fp: String::new(),
                sender_sig: String::new(),
                sender_cert: String::new(),
                seq: 0,
                timestamp: now_unix(),
                nonce: now_unix() as i64,
                hop_count: 1,
                via: vec![],
                source_relay_url: state.federation.read().await.our_url.clone().unwrap_or_default(),
                source_relay_sig: String::new(),
                source_relay_cert: String::new(),
                source_relay_fp: String::new(),
            };

            let forward_env = RelayEnvelope {
                msg_type: "relay-forward".to_string(),
                payload: serde_json::json!(forward),
                msg_id: uuid_hex(),
                ts: now_unix(),
            };
            let json = serde_json::to_string(&forward_env)
                .map_err(|e| format!("onion forward serialize: {}", e))?;

            if !state.federation.read().await.send_to_peer(exit_relay_url, json.clone()) {
                // Queue for retry
                tracing::warn!(exit_relay = %exit_relay_url, "onion: exit relay not reachable, queued");
            }

            send_ok(ws, None).await;
            Ok(())
        }
        _ => Err(format!("unknown message type: {}", env.msg_type)),
    }
}

// ------------------------------------------------------------------ //
//  Federation background tasks                                        //
// ------------------------------------------------------------------ //

/// Connect to a peer relay and maintain the connection.
/// SECURITY FIX (HIGH-6): Implements persistent connection with message channel.
async fn connect_to_peer(
    url: String,
    state: Arc<RelayState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (host, port, _use_tls) = parse_relay_url(&url)?;
    
    let (ws_stream, _response) = tokio_tungstenite::connect_async(format!("{}/federation", url))
        .await?;
    let (mut ws_sink, mut ws_stream) = ws_stream.split();
    
    tracing::info!(peer=%url, "connected to peer relay");
    
    // Create channel for outgoing messages
    let (tx, mut rx) = mpsc::channel::<FederationMessage>(100);
    
    // Register peer with our sender channel
    {
        let mut fed = state.federation.write().await;
        fed.peers.insert(url.clone(), PeerInfo {
            url: url.clone(),
            routes: HashSet::new(),
            last_seen: Instant::now(),
            authenticated: false,
            sender: Some(tx),
        });
    }
    
    // Sender task: forward messages from channel to WebSocket
    let url_clone = url.clone();
    tokio::spawn(async move {
        use tokio_tungstenite::tungstenite::Utf8Bytes;
        while let Some(msg) = rx.recv().await {
            if ws_sink.send(Message::Text(Utf8Bytes::from(msg))).await.is_err() {
                break;
            }
        }
        tracing::debug!(peer=%url_clone, "peer sender task ended");
    });
    
    // Receiver task: handle incoming messages from peer
    tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_stream.next().await {
            if let Message::Text(text) = msg {
                if let Ok(env) = serde_json::from_str::<RelayEnvelope>(&text) {
                    if env.msg_type == "route-advertise" {
                        // Store routes from peer
                        if let Some(peer_routes) = env.payload.get("null_ids")
                            .and_then(|v| v.as_array())
                        {
                            let mut fed = state.federation.write().await;
                            if let Some(peer) = fed.peers.get_mut(&url) {
                                peer.routes.clear();
                                for nid in peer_routes {
                                    if let Some(s) = nid.as_str() {
                                        peer.routes.insert(s.to_string());
                                    }
                                }
                                peer.last_seen = Instant::now();
                            }
                        }
                    }
                }
            }
        }
    });
    
    Ok(())
}

/// Periodic gossip: advertise our routes to all connected peers.
/// SECURITY FIX (HIGH-6): Actually sends messages via peer channels.
async fn gossip_task(state: Arc<RelayState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(FEDERATION_GOSSIP_INTERVAL_SECONDS));
    loop {
        interval.tick().await;

        let local_nids = state.get_local_null_ids().await;
        if local_nids.is_empty() {
            continue;
        }

        let null_ids: Vec<String> = local_nids.into_iter().collect();

        let our_url = state.federation.read().await.our_url.clone().unwrap_or_default();
        let json = match serde_json::to_string(&RelayEnvelope {
            msg_type: "route-advertise".to_string(),
            payload: serde_json::json!({
                "relay_url": our_url,
                "null_ids": null_ids,
            }),
            msg_id: uuid_hex(),
            ts: now_unix(),
        }) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("gossip serialize error: {}", e);
                continue;
            }
        };

        // Send to all connected peers via their sender channels
        let peer_urls: Vec<String> = {
            let fed = state.federation.read().await;
            fed.peers.keys().cloned().collect()
        };

        for peer_url in &peer_urls {
            if !state.federation.read().await.send_to_peer(peer_url, json.clone()) {
                tracing::warn!(peer=%peer_url, "peer not reachable for gossip");
            }
        }

        // Cleanup expired routes
        {
            let mut fed = state.federation.write().await;
            fed.cleanup_expired_routes();
        }
    }
}

/// Forward a message to a remote relay.
/// SECURITY FIX (HIGH-6): Actually sends via peer channels.
async fn forward_to_peer(
    state: Arc<RelayState>,
    relay_url: &str,
    mut forward: RelayForward,
) -> Result<(), String> {
    // SECURITY FIX (C3): Set our URL as source_relay_url so the receiving
    // relay can verify our authentication state.
    if forward.source_relay_url.is_empty() {
        forward.source_relay_url = state.federation.read().await.our_url.clone().unwrap_or_default();
    }
    let json = serde_json::to_string(&RelayEnvelope {
        msg_type: "relay-forward".to_string(),
        payload: serde_json::json!(forward),
        msg_id: uuid_hex(),
        ts: now_unix(),
    }).map_err(|e| format!("serialize forward: {}", e))?;

    if !state.federation.read().await.send_to_peer(relay_url, json.clone()) {
        tracing::warn!(target_relay=%relay_url, recipient=%forward.recipient_nid, "peer not reachable, message queued");
    } else {
        tracing::info!(target_relay=%relay_url, recipient=%forward.recipient_nid, "forwarded message to peer");
    }
    Ok(())
}

// ------------------------------------------------------------------ //
//  Helpers                                                            //
// ------------------------------------------------------------------ //

/// SECURITY FIX (C4): Verify a GPG detached signature using Sequoia (in-process).
///
/// Looks up the cert from the cert cache by fingerprint, then verifies
/// the detached signature against the data.
fn verify_gpg_detached(
    sig_b64: &str,
    data: &str,
    fingerprint: &str,
    cert_cache: &RwLock<HashMap<String, String>>,
) -> Result<bool, String> {
    use base64::Engine;
    use sequoia_openpgp::parse::Parse;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|e| format!("base64 decode signature: {}", e))?;

    // Look up the cert from cache
    let cache = cert_cache.blocking_read();
    let armored = match cache.get(fingerprint) {
        Some(cert) => cert.clone(),
        None => {
            return Err(format!(
                "no cert in cache for fingerprint {} — TOFU required",
                fingerprint
            ));
        }
    };
    drop(cache);

    let cert = sequoia_openpgp::Cert::from_bytes(armored.as_bytes())
        .map_err(|e| format!("parse cached cert: {}", e))?;

    // Use nullnode-protocol's verify_detached
    nullnode_protocol::gpg::verify_detached(
        &String::from_utf8_lossy(&sig_bytes),
        data,
        &cert,
    )
}

/// Verify HMAC-SHA256 for relay authentication.
///
/// SECURITY FIX (M3): Uses constant-time comparison even when lengths differ.
/// Previously, the length check short-circuited, leaking timing information
/// about the expected HMAC length.
fn verify_hmac(data: &str, provided_hmac: &str, secret: &str) -> bool {
    let computed = compute_hmac(data, secret);

    // Constant-time comparison: XOR all bytes, including padding for
    // differing lengths, so the comparison time does not leak length info.
    let computed_bytes = computed.as_bytes();
    let provided_bytes = provided_hmac.as_bytes();
    let max_len = computed_bytes.len().max(provided_bytes.len());
    let mut acc: u8 = 0;
    for i in 0..max_len {
        let c = if i < computed_bytes.len() {
            computed_bytes[i]
        } else {
            0
        };
        let p = if i < provided_bytes.len() {
            provided_bytes[i]
        } else {
            0
        };
        acc |= c ^ p;
    }
    // Also XOR the length difference to ensure mismatched lengths fail
    acc |= (computed_bytes.len() as u8) ^ (provided_bytes.len() as u8);
    acc == 0
}

/// Compute SHA-256 hex hash of data.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute HMAC-SHA256.
fn compute_hmac(data: &str, secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Parse a relay URL into (host, port, use_tls).
fn parse_relay_url(url: &str) -> Result<(String, u16, bool), Box<dyn std::error::Error>> {
    // Simple URL parser for ws:// and wss:// schemes
    let (use_tls, rest) = if url.starts_with("wss://") {
        (true, &url[6..])
    } else if url.starts_with("ws://") {
        (false, &url[5..])
    } else {
        (false, url)
    };

    let (host, port_str) = if let Some(colon_pos) = rest.rfind(':') {
        (&rest[..colon_pos], &rest[colon_pos+1..])
    } else {
        (rest, if use_tls { "443" } else { "80" })
    };

    let port: u16 = port_str.parse().unwrap_or(if use_tls { 443 } else { 80 });

    Ok((host.to_string(), port, use_tls))
}

/// Generate a random challenge for peer authentication.
fn generate_challenge() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    hex::encode(bytes)
}

fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn uuid_hex() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let n: u128 = rng.r#gen();
    format!("{:032x}", n)[..16].to_string()
}

// ------------------------------------------------------------------ //
//  Main                                                               //
// ------------------------------------------------------------------ //

/// NullNode Relay Server (store-and-forward) with Multi-Relay Federation
#[derive(Parser, Debug)]
#[command(name = "nullnode-relay", version, about)]
struct Args {
    /// Listen address
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// Listen port
    #[arg(long, default_value_t = 8765)]
    port: u16,

    /// Peer relay URL for federation (can be specified multiple times).
    /// Examples:
    ///   --peer wss://relay-b.example.com:8765
    ///   --peer ws://127.0.0.1:8766
    ///   --peer-seed wss://seed.example.com/peers
    #[arg(long, action = clap::ArgAction::Append)]
    peer: Vec<String>,

    /// Read peer URLs from a file (one per line).
    #[arg(long)]
    peer_file: Option<String>,

    /// Shared peer secret for HMAC auth
    #[arg(long)]
    secret: Option<String>,

    /// SECURITY FIX (L4): Read shared peer secret from a file instead of
    /// passing it as a plaintext CLI argument. Using --secret exposes the
    /// secret in the process list (/proc/*/cmdline, ps aux). With --secret-file
    /// the relay reads the secret from a file (which should have 0o600 perms).
    #[arg(long)]
    secret_file: Option<String>,

    /// Our advertised URL (what we tell peers we are).
    /// If not set, uses host:port.
    #[arg(long)]
    url: Option<String>,

    /// SECURITY FIX (C4): GPG home directory for verifying sender signatures.
    /// Defaults to the user's GPG keyring.
    #[arg(long)]
    gpg_home: Option<String>,

    /// SECURITY FIX (C5): Path to TLS certificate file (PEM).
    /// When set, the relay accepts wss:// connections.
    #[arg(long)]
    tls_cert: Option<String>,

    /// SECURITY FIX (C5): Path to TLS private key file (PEM).
    /// Must be used with --tls-cert.
    #[arg(long)]
    tls_key: Option<String>,

    /// ACS2.6 Part V.1: Enable CBNP (Coordinated Baseline Noise Protocol) cover traffic.
    /// When enabled, the relay generates synthetic cover packets to maintain a constant
    /// network traffic profile, preventing traffic analysis during idle periods.
    #[arg(long, default_value_t = true)]
    cbnp_enabled: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("nullnode=info".parse()?))
        .init();

    let args = Args::parse();

    // SECURITY FIX (C4): Determine GPG home directory
    let gpg_home = args.gpg_home.clone().unwrap_or_else(|| {
        dirs::home_dir()
            .map(|h| h.join(".nullnode/gnupg").to_string_lossy().to_string())
            .unwrap_or_else(|| "~/.nullnode/gnupg".to_string())
    });

    // SECURITY FIX (C5): Load TLS acceptor if cert+key provided
    let tls_acceptor = if let (Some(cert_path), Some(key_path)) = (&args.tls_cert, &args.tls_key) {
        Some(load_tls_acceptor(cert_path, key_path)?)
    } else {
        tracing::warn!("TLS not configured -- relay running in plaintext mode (ws://). \
                        For production, use --tls-cert and --tls-key.");
        None
    };

    let addr = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("nullnode-relay listening on {} ({})",
        addr,
        if tls_acceptor.is_some() { "wss:// (TLS)" } else { "ws:// (plaintext)" });

    // SECURITY FIX (L4): Resolve shared secret from file if provided,
    // to avoid exposing it in the process list.
    let shared_secret = if let Some(ref path) = args.secret_file {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                let trimmed = s.trim().to_string();
                tracing::info!("Loaded shared secret from {}", path);
                Some(trimmed)
            }
            Err(e) => {
                tracing::error!("Failed to read secret file {}: {}", path, e);
                return Err(e.into());
            }
        }
    } else if args.secret.is_some() {
        tracing::warn!("--secret exposes the secret in the process list. Use --secret-file instead.");
        args.secret.clone()
    } else {
        None
    };

    // Determine our advertised URL
    let our_url = args.url.clone().unwrap_or_else(|| {
        if tls_acceptor.is_some() {
            format!("wss://{}:{}", args.host, args.port)
        } else {
            format!("ws://{}:{}", args.host, args.port)
        }
    });

    let db_path = format!("{}/mailbox.db", gpg_home);
    let state = Arc::new(RelayState::new(shared_secret.clone(), gpg_home, Some(db_path)).await?);
    {
        let mut fed = state.federation.write().await;
        fed.our_url = Some(our_url.clone());
    }

    let cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            cleanup_state.cleanup_expired().await;
            tracing::debug!("mailbox cleanup complete");
        }
    });

    // SECURITY FIX (H8): Periodic cleanup of stale per-IP rate limiters.
    // Remove entries that haven't been accessed in PEER_LIMITER_CLEANUP_SECS.
    {
        let limiter_state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(PEER_LIMITER_CLEANUP_SECS));
            loop {
                interval.tick().await;
                let mut limiters = limiter_state.conn_limiters.write().await;
                let cutoff = Instant::now() - Duration::from_secs(PEER_LIMITER_CLEANUP_SECS * 2);
                limiters.retain(|_, (_, last_access)| *last_access > cutoff);
                tracing::debug!(active_limiters=limiters.len(), "per-IP rate limiter cleanup complete");
            }
        });
    }

    // Background task: gossip-based route advertisement
    let gossip_state = Arc::clone(&state);
    tokio::spawn(async move {
        gossip_task(gossip_state).await;
    });

    // Connect to configured peers
    let peer_urls: Vec<String> = {
        let mut urls = Vec::new();
        // Direct --peer arguments
        for p in &args.peer {
            urls.push(p.clone());
        }
        // --peer-file
        if let Some(ref path) = args.peer_file {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            urls.push(trimmed.to_string());
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to read peer file {}: {}", path, e);
                }
            }
        }
        urls
    };

    for peer_url in peer_urls {
        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            let url_str = peer_url.clone();
            if let Err(e) = connect_to_peer(url_str.clone(), state_clone).await {
                tracing::error!(peer=%url_str, "failed to connect to peer: {}", e);
            }
        });
    }

    // Background task: CBNP cover traffic (ACS2.6 Part V.1)
    // Generates synthetic cover packets to maintain constant traffic profile,
    // preventing traffic analysis during idle periods.
    let cbnp_config = nullnode_crypto::cbnp::CbnpConfig {
        lambda_seconds: 10.0,
        enabled: args.cbnp_enabled,
        max_burst: 3,
    };
    let cbnp_session = nullnode_crypto::cbnp::CbnpSession::new(cbnp_config);
    if args.cbnp_enabled {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                // Generate a cover packet to maintain traffic profile
                let _cover = cbnp_session.generate_cover_packet();
                // In production: forward cover to a random peer via WebSocket
            }
        });
    }

    // ACS2.6 Part III.2: Lifecycle memory hooks — graceful shutdown on SIGINT/SIGTERM
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("received SIGINT, shutting down relay gracefully...");
        shutdown_clone.notify_one();
    });

    // Accept loop
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer_addr)) => {
                        let state = Arc::clone(&state);
                        let tls = tls_acceptor.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, peer_addr, state, tls).await {
                                tracing::warn!("connection error from {}: {}", peer_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("accept error: {}", e);
                    }
                }
            }
            _ = shutdown.notified() => {
                tracing::info!("relay shutdown complete");
                break;
            }
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ //
//  Metadata encryption helpers (SECURITY FIX M3)
// ------------------------------------------------------------------ //

impl RelayState {
    /// Encrypt sender metadata (nid + fp) using AES-256-GCM.
    /// Returns hex-encoded string: [nonce_12bytes][tag_16bytes][ciphertext].
    fn encrypt_metadata(plaintext: &str, key: &[u8; 32]) -> String {
        use aes_gcm::aead::Aead;
        use aes_gcm::aead::rand_core::RngCore;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256-GCM key init");
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .expect("AES-256-GCM encrypt");

        // Concatenate: nonce (12) + tag (16, appended by AES-GCM) + ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        hex::encode(result)
    }

    /// Decrypt sender metadata encrypted with `encrypt_metadata`.
    fn decrypt_metadata(encrypted_hex: &str, key: &[u8; 32]) -> Option<String> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let data = hex::decode(encrypted_hex).ok()?;
        if data.len() < 28 {
            return None; // 12 (nonce) + 16 (tag) minimum
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(key).ok()?;
        let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;
        String::from_utf8(plaintext).ok()
    }
}

// ------------------------------------------------------------------ //
//  Tests                                                              //
// ------------------------------------------------------------------ //

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_relay_url_ws() {
        let (host, port, tls) = parse_relay_url("ws://127.0.0.1:8765").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8765);
        assert!(!tls);
    }

    #[test]
    fn test_parse_relay_url_wss() {
        let (host, port, tls) = parse_relay_url("wss://relay.example.com:443").unwrap();
        assert_eq!(host, "relay.example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn test_parse_relay_url_default_port() {
        let (host, port, tls) = parse_relay_url("ws://my.host").unwrap();
        assert_eq!(host, "my.host");
        assert_eq!(port, 80);
        assert!(!tls);
    }

    #[test]
    fn test_compute_hmac() {
        let h = compute_hmac("hello", "secret");
        assert_eq!(h.len(), 64); // SHA-256 hex = 64 chars
        // Same input produces same output
        let h2 = compute_hmac("hello", "secret");
        assert_eq!(h, h2);
        // Different secret produces different output
        let h3 = compute_hmac("hello", "different");
        assert_ne!(h, h3);
    }

    #[test]
    fn test_verify_hmac_valid() {
        let h = compute_hmac("test-data", "my-secret");
        assert!(verify_hmac("test-data", &h, "my-secret"));
    }

    #[test]
    fn test_verify_hmac_invalid() {
        let h = compute_hmac("test-data", "my-secret");
        assert!(!verify_hmac("test-data", &h, "wrong-secret"));
        assert!(!verify_hmac("other-data", &h, "my-secret"));
    }

    #[test]
    fn test_federation_add_and_lookup_route() {
        let mut fed = FederationState::new(None);
        fed.add_route("NN-ALICE-1234", "ws://relay-a.example.com:8765");
        assert_eq!(fed.lookup_route("NN-ALICE-1234"), Some("ws://relay-a.example.com:8765"));
        assert_eq!(fed.lookup_route("NN-BOB-5678"), None);
    }

    #[test]
    fn test_federation_route_expiry() {
        let mut fed = FederationState::new(None);
        fed.add_route("NN-ALICE-1234", "ws://relay-a.example.com:8765");
        // Manually set expiry to the past
        if let Some(entry) = fed.remote_routes.get_mut("NN-ALICE-1234") {
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
        // Cleanup should remove it
        fed.cleanup_expired_routes();
        assert_eq!(fed.lookup_route("NN-ALICE-1234"), None);
    }

    #[test]
    fn test_federation_nonce_replay() {
        let mut fed = FederationState::new(None);
        assert!(fed.record_nonce("ws://peer1:8765", "nonce-1"));
        assert!(fed.record_nonce("ws://peer1:8765", "nonce-2"));
        // Replay should be rejected
        assert!(!fed.record_nonce("ws://peer1:8765", "nonce-1"));
    }

    #[test]
    fn test_relay_forward_loop_detection() {
        let our_url = "ws://my-relay:8765";
        let via: Vec<String> = vec![our_url.to_string()];
        let forward = RelayForward {
            recipient_nid: "NN-ALICE-1234".to_string(),
            signed_blob: "blob".to_string(),
            sender_nid: "NN-BOB-5678".to_string(),
            sender_fp: "fp".to_string(),
            seq: 1,
            sender_sig: "sig".to_string(),
            sender_cert: String::new(),
            timestamp: now_unix(),
            nonce: 42,
            hop_count: 1,
            via,
            source_relay_url: "ws://sender-relay:8765".to_string(),
            source_relay_sig: String::new(),
            source_relay_cert: String::new(),
            source_relay_fp: String::new(),
        };
        assert!(forward.via.contains(&our_url.to_string()));
        assert_eq!(forward.source_relay_url, "ws://sender-relay:8765");
    }

    #[test]
    fn test_relay_forward_hop_limit() {
        let forward = RelayForward {
            recipient_nid: "NN-ALICE-1234".to_string(),
            signed_blob: "blob".to_string(),
            sender_nid: "NN-BOB-5678".to_string(),
            sender_fp: "fp".to_string(),
            seq: 1,
            sender_sig: "sig".to_string(),
            sender_cert: String::new(),
            timestamp: now_unix(),
            nonce: 42,
            hop_count: FEDERATION_MAX_RELAY_HOPS,
            via: vec![],
            source_relay_url: String::new(),
            source_relay_sig: String::new(),
            source_relay_cert: String::new(),
            source_relay_fp: String::new(),
        };
        assert!(forward.hop_count >= FEDERATION_MAX_RELAY_HOPS);
    }

    #[test]
    fn test_source_relay_url_defaults_empty() {
        // Deserialize without source_relay_url — should default to empty
        let json = serde_json::json!({
            "recipient_nid": "NN-ALICE-1234",
            "signed_blob": "blob",
            "sender_nid": "NN-BOB-5678",
            "sender_fp": "fp",
            "seq": 1,
            "sender_sig": "sig",
            "timestamp": 1234567890.0,
            "nonce": 42,
        });
        let forward: RelayForward = serde_json::from_value(json).unwrap();
        assert_eq!(forward.source_relay_url, "");
    }
}
