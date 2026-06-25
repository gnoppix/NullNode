//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{info, warn, debug, error};
use futures::{SinkExt, StreamExt};

use nullnode_protocol::constants;
use nullnode_protocol::envelope::*;
use nullnode_protocol::pow::pow_check;

use crate::bot_log::BotLogger;
use crate::crypto_helpers::{compute_null_id, verify_signature, verify_signature_with_cert, validate_fingerprint, validate_null_id};
use crate::ratelimit::RateLimiter;
use crate::sqlite_store::DhtStore;
use crate::types::{DhtNode, NodeConfig};
use crate::DhtResult;

/// SECURITY FIX (C6): TLS acceptor for the DHT WebSocket server.
/// When configured, the DHT node accepts wss:// connections.
type DhtTlsAcceptor = tokio_rustls::TlsAcceptor;

/// SECURITY FIX (C6): Combined trait for boxing streams (TLS or plaintext).
trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T> AsyncReadWrite for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// SECURITY FIX (C6): Load a TLS acceptor from PEM cert and key files.
fn load_dht_tls_acceptor(
    cert_path: &str,
    key_path: &str,
) -> Result<DhtTlsAcceptor, Box<dyn std::error::Error>> {
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

/// Async runtime for a DHT node (WebSocket server + request handler).
pub struct DhtNodeRuntime {
    pub node: DhtNode,
    pub store: DhtStore,
    pub config: NodeConfig,
    pub conn_limiter: RateLimiter,
    /// SECURITY FIX (M7): Per-IP rate limiter for GET operations.
    /// Prevents key enumeration / scanning attacks.
    pub get_limiter: RateLimiter,
    stealth_mode: bool,
    seen_nonces: Arc<RwLock<HashMap<String, HashSet<i64>>>>,
    bot_logger: BotLogger,
}

impl DhtNodeRuntime {
    /// Create a new DHT node runtime.
    pub async fn new(config: NodeConfig) -> DhtResult<Self> {
        let store = DhtStore::open(config.db_path.as_deref()).await?;
        let node_id = DhtNode::node_id_from_nid(&config.null_id);

        let node = DhtNode {
            null_id: config.null_id.clone(),
            fingerprint: config.fingerprint.clone(),
            node_id,
            host: config.host.clone(),
            port: config.port,
            address: format!("{}:{}", config.host, config.port),
            routing_table: HashMap::new(),
        };

        let conn_limiter = RateLimiter::new(
            constants::CONN_RATE_LIMIT as usize,
            constants::CONN_RATE_WINDOW as f64,
        );
        // SECURITY FIX (M7): Tighter rate limit for GET operations (30 per 60s per IP)
        let get_limiter = RateLimiter::new(30, 60.0);
        let bot_logger = BotLogger::new(None);

        Ok(Self {
            node,
            store,
            config,
            conn_limiter,
            get_limiter,
            stealth_mode: false,
            seen_nonces: Arc::new(RwLock::new(HashMap::new())),
            bot_logger,
        })
    }

    /// Start the DHT node WebSocket server. Blocks until shutdown.
    pub async fn start(self) -> DhtResult<()> {
        let addr = format!("{}:{}", self.config.host, self.config.port);

        // SECURITY FIX (C6): Load TLS acceptor if cert and key are configured
        let tls_acceptor: Option<DhtTlsAcceptor> = if !self.config.ssl_certfile.is_empty() && !self.config.ssl_keyfile.is_empty() {
            match load_dht_tls_acceptor(&self.config.ssl_certfile, &self.config.ssl_keyfile) {
                Ok(a) => {
                    info!("DHT node TLS configured: cert={}", self.config.ssl_certfile);
                    Some(a)
                }
                Err(e) => {
                    error!("Failed to load DHT TLS cert/key: {} — falling back to plaintext", e);
                    None
                }
            }
        } else {
            warn!("DHT node TLS not configured (ssl_certfile/ssl_keyfile empty) — running in plaintext mode (ws://). \
                  For production, set ssl_certfile and ssl_keyfile in NodeConfig.");
            None
        };

        let listener = TcpListener::bind(&addr).await?;
        info!("DHT node listening on {} ({})", addr,
            if tls_acceptor.is_some() { "wss:// (TLS)" } else { "ws:// (plaintext)" });

        let store = self.store;
        let stealth = self.stealth_mode;
        let seen_nonces = self.seen_nonces;
        let bot = self.bot_logger;
        let get_limiter = self.get_limiter;

        // SECURITY FIX (L3): Background cleanup of seen_nonces to prevent
        // unbounded memory growth. An attacker can send puts with many
        // different keys, each creating a HashSet entry that is never removed.
        // This task prunes entries every 5 minutes, removing keys whose
        // nonce sets have grown large (keeping only the most recent 64).
        {
            let nonces_for_prune = seen_nonces.clone();
            tokio::spawn(async move {
                let interval = std::time::Duration::from_secs(300);
                loop {
                    tokio::time::sleep(interval).await;
                    let mut nonces = nonces_for_prune.write().await;
                    // For each key, if the set has more than 64 nonces,
                    // keep only the most recent 64 (prevents unbounded growth
                    // per key from a legitimate high-volume publisher).
                    for (_key, set) in nonces.iter_mut() {
                        if set.len() > 64 {
                            let mut all: Vec<i64> = set.iter().copied().collect();
                            all.sort_unstable();
                            let to_keep = &all[all.len() - 64..];
                            set.clear();
                            for n in to_keep {
                                set.insert(*n);
                            }
                        }
                    }
                    // Remove keys with empty sets
                    nonces.retain(|_, set| !set.is_empty());
                }
            });
        }

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let peer_ip = peer_addr.ip().to_string();

            let allowed = self.conn_limiter.allow(&peer_ip).await;
            if !allowed {
                warn!("rate-limited connection from {}", peer_addr);
                continue;
            }

            let store_clone = store.clone();
            let bot_clone = bot.clone();
            let nonces_clone = seen_nonces.clone();
            let tls = tls_acceptor.clone();
            let get_lim = get_limiter.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(
                    stream, peer_addr, &store_clone, stealth, nonces_clone, bot_clone, tls, get_lim,
                ).await {
                    debug!("connection from {} closed: {}", peer_addr, e);
                }
            });
        }
    }

    async fn handle_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        store: &DhtStore,
        stealth_mode: bool,
        seen_nonces: Arc<RwLock<HashMap<String, HashSet<i64>>>>,
        bot_logger: BotLogger,
        tls_acceptor: Option<DhtTlsAcceptor>,
        get_limiter: RateLimiter,
    ) -> DhtResult<()> {
        // SECURITY FIX (C6): Wrap stream in TLS if acceptor is configured.
        // We box the underlying stream so both TLS and plaintext paths produce
        // the same WebSocketStream type.
        type BoxedStream = Box<dyn AsyncReadWrite>;
        let ws = if let Some(acceptor) = tls_acceptor {
            let tls_stream = acceptor.accept(stream).await.map_err(|e| {
                crate::DhtError::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
            })?;
            let boxed: BoxedStream = Box::new(tls_stream);
            accept_async(boxed).await.map_err(|e| {
                crate::DhtError::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
            })?
        } else {
            let boxed: BoxedStream = Box::new(stream);
            accept_async(boxed).await.map_err(|e| {
                crate::DhtError::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
            })?
        };

        let (mut ws_tx, mut ws_rx) = ws.split();
        let mut consecutive_failures: u32 = 0;
        const MAX_FAILURES: u32 = 10;

        while let Some(msg_result) = ws_rx.next().await {
            let raw = match msg_result {
                Ok(Message::Text(text)) => text.to_string(),
                Ok(Message::Close(_)) => break,
                Ok(_) => continue,
                Err(e) => {
                    debug!("websocket error from {}: {}", peer_addr, e);
                    break;
                }
            };

            let env = match WireEnvelope::from_json(&raw) {
                Ok(e) => e,
                Err(e) => {
                    consecutive_failures += 1;
                    if consecutive_failures == MAX_FAILURES {
                        bot_logger.log(
                            &peer_addr.ip().to_string(),
                            peer_addr.port(),
                            "SCANNER",
                            Some(&format!("bad_envelope x{MAX_FAILURES}")),
                        );
                    }
                    if stealth_mode {
                        let _ = ws_tx.send(Message::Text(Self::stealth_response().into())).await;
                    } else {
                        let resp = build_dht_error("", &format!("bad envelope: {e}"));
                        let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
                    }
                    continue;
                }
            };

            // Timestamp freshness check
            let now = now_unix();
            if (now - env.ts).abs() > constants::POW_MAX_AGE as f64 {
                consecutive_failures += 1;
                if consecutive_failures == MAX_FAILURES {
                    bot_logger.log(
                        &peer_addr.ip().to_string(),
                        peer_addr.port(),
                        "SCANNER",
                        Some(&format!("stale_timestamp x{MAX_FAILURES}")),
                    );
                }
                if stealth_mode {
                    let _ = ws_tx.send(Message::Text(Self::stealth_response().into())).await;
                } else {
                    let key = env.payload_str("key").unwrap_or("");
                    let resp = build_dht_error(key, "stale timestamp");
                    let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
                }
                continue;
            }

            consecutive_failures = 0;

            match env.msg_type.as_str() {
                "dht-put" => {
                    Self::handle_put(&env, &mut ws_tx, store, stealth_mode, &seen_nonces, &bot_logger, &peer_addr).await;
                }
                "dht-get" => {
                    // SECURITY FIX (M7): Per-IP rate limiting for GET operations
                    // to prevent key enumeration / scanning attacks.
                    let peer_ip = peer_addr.ip().to_string();
                    if !get_limiter.allow(&peer_ip).await {
                        bot_logger.log(
                            &peer_ip,
                            peer_addr.port(),
                            "GET_RATE_LIMITED",
                            Some("dht-get rate limit exceeded"),
                        );
                        if stealth_mode {
                            let _ = ws_tx.send(Message::Text(Self::stealth_response().into())).await;
                        } else {
                            let resp = build_dht_error("", "rate limited");
                            let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
                        }
                        continue;
                    }
                    Self::handle_get(&env, &mut ws_tx, store, stealth_mode).await;
                }
                "dht-addr-record" => {
                    Self::handle_addr_record(&env, &mut ws_tx, store, stealth_mode).await;
                }
                other => {
                    bot_logger.log(
                        &peer_addr.ip().to_string(),
                        peer_addr.port(),
                        "BAD_TYPE",
                        Some(other),
                    );
                    if stealth_mode {
                        let _ = ws_tx.send(Message::Text(Self::stealth_response().into())).await;
                    } else {
                        let key = env.payload_str("key").unwrap_or("");
                        let resp = build_dht_error(key, &format!("unexpected type: {other}"));
                        let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
                    }
                }
            }
        }

        if consecutive_failures >= 5 {
            bot_logger.log(
                &peer_addr.ip().to_string(),
                peer_addr.port(),
                "SUSPECT",
                Some(&format!("{consecutive_failures} consecutive failures")),
            );
        }

        Ok(())
    }

    async fn handle_put(
        env: &WireEnvelope,
        ws_tx: &mut (impl futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
        store: &DhtStore,
        _stealth_mode: bool,
        seen_nonces: &RwLock<HashMap<String, HashSet<i64>>>,
        _bot_logger: &BotLogger,
        _peer_addr: &SocketAddr,
    ) {
        let key = env.payload_str("key").unwrap_or("").to_string();
        let value_b64 = env.payload_str("value").unwrap_or("").to_string();
        let salt = env.payload_str("salt").unwrap_or("").to_string();
        let seq = env.payload_i64("seq").unwrap_or(0);
        let ttl = env.payload_i64("ttl").unwrap_or(constants::STORE_TTL).min(constants::STORE_TTL);
        let nonce = env.payload_i64("nonce").unwrap_or(0);
        let sig = env.sig.clone();

        if !validate_null_id(&key) {
            let resp = build_dht_error(&key, "invalid key format");
            let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            return;
        }

        // SECURITY FIX (M4): Enforce global key count limit to prevent
        // resource exhaustion. Without this, an attacker could fill the
        // DHT store with unlimited keys, exhausting disk/memory.
        // SECURITY FIX (L2): Check regardless of whether sig is present.
        // Even though unsigned puts are rejected later, the count check
        // must run first as defense-in-depth.
        {
            let exists = store.has_key(&key).await.unwrap_or(false);
            if !exists {
                let count = store.count_keys().await.unwrap_or(0);
                if count >= constants::MAX_TOTAL_KEYS as i64 {
                    let resp = build_dht_error(&key, "DHT store full (max keys reached)");
                    let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
                    return;
                }
            }
        }

        if value_b64.len() > constants::MAX_VALUE_SIZE {
            let resp = build_dht_error(&key, "value too large");
            let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            return;
        }

        // Anti-replay: check nonce
        {
            let nonces = seen_nonces.read().await;
            if nonces.get(&key).map_or(false, |s| s.contains(&nonce)) {
                let resp = build_dht_error(&key, "nonce replay");
                let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
                return;
            }
        }

        // Verify proof-of-work
        let pow_data = format!("{key}{value_b64}{salt}{seq}");
        let pow_ok = pow_check(&pow_data, nonce as u64, constants::DHT_POW_DIFFICULTY).unwrap_or(false);
        if !pow_ok {
            let resp = build_dht_error(&key, "insufficient proof-of-work");
            let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            return;
        }

        if sig.is_empty() {
            let resp = build_dht_error(&key, "missing signature");
            let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            return;
        }

        let publisher_fp = env.payload_str("publisher_fp").unwrap_or("").to_string();
        if !validate_fingerprint(&publisher_fp) {
            let resp = build_dht_error(&key, "invalid publisher fingerprint");
            let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            return;
        }

        let expected_nid = compute_null_id(&publisher_fp);
        if expected_nid != key {
            let resp = build_dht_error(&key, &format!("key mismatch: expected {expected_nid}"));
            let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            return;
        }

        let sign_data = format!("{key}|{value_b64}|{salt}|{seq}|{nonce}");
        // Try cert-based verification first (preferred path)
        let verified = if let Some(cert_armored) = env.payload_str("publisher_cert") {
            use sequoia_openpgp::parse::Parse;
            if let Ok(cert) = sequoia_openpgp::Cert::from_bytes(cert_armored.as_bytes()) {
                verify_signature_with_cert(&sign_data, &sig, &cert)
            } else {
                false
            }
        } else {
            verify_signature(&sign_data, &sig, &publisher_fp)
        };
        if !verified {
            let resp = build_dht_error(&key, "signature verification failed");
            let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            return;
        }

        match store.put(&key, &value_b64, &salt, seq, &publisher_fp, ttl, &sig).await {
            Ok(true) => {
                let mut nonces = seen_nonces.write().await;
                nonces.entry(key.clone()).or_default().insert(nonce);

                let resp = build_dht_found(&key, &value_b64, &salt, seq);
                let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
                debug!("stored key {} seq {}", key, seq);
            }
            Ok(false) => {
                let resp = build_dht_error(&key, "stale sequence");
                let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            }
            Err(e) => {
                error!("storage error for key {}: {}", key, e);
                let resp = build_dht_error(&key, "storage error");
                let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            }
        }
    }

    async fn handle_get(
        env: &WireEnvelope,
        ws_tx: &mut (impl futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
        store: &DhtStore,
        stealth_mode: bool,
    ) {
        let key = env.payload_str("key").unwrap_or("");

        if !validate_null_id(key) {
            if stealth_mode {
                let _ = ws_tx.send(Message::Text(Self::stealth_response().into())).await;
            } else {
                let resp = build_dht_error(key, "invalid key format");
                let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            }
            return;
        }

        match store.get(key).await {
            Ok(Some(record)) => {
                let resp = build_dht_found(key, &record.value, &record.salt, record.seq);
                let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            }
            Ok(None) => {
                let resp = build_dht_error(key, "not found");
                let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            }
            Err(e) => {
                error!("get error for key {}: {}", key, e);
                let resp = build_dht_error(key, "storage error");
                let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            }
        }
    }

    async fn handle_addr_record(
        env: &WireEnvelope,
        ws_tx: &mut (impl futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
        store: &DhtStore,
        _stealth_mode: bool,
    ) {
        let null_id = env.payload_str("null_id").unwrap_or("").to_string();
        let address = env.payload_str("address").unwrap_or("").to_string();
        let ttl = env.payload_i64("ttl").unwrap_or(constants::ADDR_TTL);
        let publisher_fp = env.payload_str("publisher_fp").unwrap_or("").to_string();
        let nonce = env.payload_i64("nonce").unwrap_or(0);
        let sig = env.sig.clone();

        if !validate_null_id(&null_id) {
            let resp = build_dht_error(&null_id, "invalid null_id format");
            let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            return;
        }

        if !validate_fingerprint(&publisher_fp) {
            let resp = build_dht_error(&null_id, "invalid publisher fingerprint");
            let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            return;
        }

        let expected_nid = compute_null_id(&publisher_fp);
        if expected_nid != null_id {
            let resp = build_dht_error(&null_id, &format!("null_id mismatch: expected {expected_nid}"));
            let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            return;
        }

        let sign_data = format!("{null_id}|{address}|{ttl}");
        // Try cert-based verification first (preferred path)
        let verified = if let Some(cert_armored) = env.payload_str("publisher_cert") {
            use sequoia_openpgp::parse::Parse;
            if let Ok(cert) = sequoia_openpgp::Cert::from_bytes(cert_armored.as_bytes()) {
                verify_signature_with_cert(&sign_data, &sig, &cert)
            } else {
                false
            }
        } else {
            verify_signature(&sign_data, &sig, &publisher_fp)
        };
        if !verified {
            let resp = build_dht_error(&null_id, "signature verification failed");
            let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            return;
        }

        // SECURITY FIX (L7): Require proof-of-work for addr-record writes.
        // Without this, an attacker could flood the DHT with address records
        // (which are cheaper than full DHT puts since they don't require
        // the Argon2id PoW that handle_put enforces).
        let pow_data = format!("{null_id}{address}{ttl}");
        let pow_ok = pow_check(&pow_data, nonce as u64, constants::ADDR_POW_DIFFICULTY).unwrap_or(false);
        if !pow_ok {
            let resp = build_dht_error(&null_id, "insufficient proof-of-work");
            let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            return;
        }

        let salt = format!("addr:{}", rand::random::<u32>());
        let seq = now_unix() as i64;
        match store.put(&null_id, &address, &salt, seq, &publisher_fp, ttl, &sig).await {
            Ok(true) => {
                let resp = build_dht_found(&null_id, &address, &salt, seq);
                let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            }
            Ok(false) => {
                let resp = build_dht_error(&null_id, "stale sequence");
                let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            }
            Err(e) => {
                error!("addr-record storage error: {}", e);
                let resp = build_dht_error(&null_id, "storage error");
                let _ = ws_tx.send(Message::Text(resp.to_json().unwrap_or_default().into())).await;
            }
        }
    }

    fn stealth_response() -> String {
        let payload = serde_json::json!({ "key": "", "value": "", "salt": "", "seq": 0 });
        serde_json::json!({
            "type": "dht-found",
            "payload": payload,
            "msg_id": uuid_hex(),
            "ts": now_unix(),
            "sig": "",
        })
        .to_string()
    }
}

/// Extract the peer (host, port) from a TCP stream.
pub fn get_peer_address(stream: &TcpStream) -> (String, u16) {
    match stream.peer_addr() {
        Ok(addr) => (addr.ip().to_string(), addr.port()),
        Err(_) => ("unknown".to_string(), 0),
    }
}

fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
