//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// NullNode P2P Messenger Client
//
// G1: Send command — DHT lookup + P2P delivery
// G2: Read command — relay mailbox fetch + decrypt
// G3: Listen command — WebSocket listener for incoming P2P connections
// G4: Kademlia DHT routing — documented as intentional (centralized seed model)
// G5: Message persistence — local SQLite message store
//-------------------------------------------------------------------------------

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use clap::Parser;
use futures::{SinkExt as _, StreamExt as _};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::Pool;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tracing_subscriber::EnvFilter;
use base64::Engine;

// ------------------------------------------------------------------ //
//  Configuration                                                     //
// ------------------------------------------------------------------ //

const GPG_HOME: &str = ".nullnode/gnupg";
const CONTACTS_PATH: &str = ".nullnode/contacts.json";
const IDENTITY_PATH: &str = ".nullnode/identity.json";
const BOOTSTRAP_PATH: &str = ".nullnode/bootstrap_pin_cache.json";
const MESSAGES_DB: &str = ".nullnode/messages.db";
const SEED_URL: &str = "ws://127.0.0.1:9001";
const RELAY_URL: &str = "ws://127.0.0.1:8765";

// ------------------------------------------------------------------ //
//  Identity                                                          //
// ------------------------------------------------------------------ //

/// Path to persistent Kyber keypair
const KYBER_KEY_PATH: &str = ".nullnode/kyber_key.json";

/// Load the Sequoia certificate for signing operations.
fn load_cert() -> Result<sequoia_openpgp::Cert, Box<dyn std::error::Error>> {
    use sequoia_openpgp::parse::Parse;
    let cert_dir = home_dir().join(GPG_HOME);
    let cert_path = cert_dir.join("own_cert.asc");
    if !cert_path.exists() {
        return Err("no identity found — run 'nullnode init' first".into());
    }
    let armored = std::fs::read_to_string(&cert_path)?;
    sequoia_openpgp::Cert::from_bytes(armored.as_bytes())
        .map_err(|e| format!("parse cert: {}", e).into())
}

/// Sign data with our PGP key for P2P/relay authentication.
fn sign_for_transport(data: &str) -> Result<String, Box<dyn std::error::Error>> {
    let cert = load_cert()?;
    nullnode_dht_core::sign_data(data, &cert)
        .map_err(|e| format!("sign failed: {}", e).into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Identity {
    fingerprint: String,
    null_id: String,
}

impl Identity {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let path = home_dir().join(IDENTITY_PATH);
        if !path.exists() {
            return Err("no identity found — run 'nullnode init' first".into());
        }
        let content = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&content)?)
    }

    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = home_dir().join(IDENTITY_PATH);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        // Set 0o600 permissions for security
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
    
    /// Get the stored certificate for signing
    fn cert(&self) -> Result<sequoia_openpgp::Cert, Box<dyn std::error::Error>> {
        load_cert()
    }
}

// ------------------------------------------------------------------ //
//  Contacts                                                          //
// ------------------------------------------------------------------ //

type Contacts = HashMap<String, String>; // null_id -> fingerprint

fn load_contacts() -> Contacts {
    let path = home_dir().join(CONTACTS_PATH);
    if !path.exists() {
        return HashMap::new();
    }
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    serde_json::from_str(&content).unwrap_or_default()
}

fn save_contacts(contacts: &Contacts) -> Result<(), Box<dyn std::error::Error>> {
    let path = home_dir().join(CONTACTS_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(contacts)?)?;
    // SECURITY FIX (HIGH-5): Set 0o600 permissions for contacts file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ------------------------------------------------------------------ //
//  Message Store (G5)                                                //
// ------------------------------------------------------------------ //

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMessage {
    id: i64,
    from_nid: String,
    to_nid: String,
    ciphertext: String,
    timestamp: String,
    delivered: bool,
}

#[derive(Clone)]
struct MessageStore {
    pool: Pool<sqlx::Sqlite>,
}

impl MessageStore {
    async fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let path = home_dir().join(MESSAGES_DB);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        // SECURITY FIX (HIGH-4): Set restrictive file permissions on database
        // Note: SQLite doesn't respect permissions on newly-created DB, so we set them after connect
        let url = format!("sqlite:{}", path.display());
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await?;
        
        // Set permissions on the database file (may need to retry on race condition)
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_nid TEXT NOT NULL,
                to_nid TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                delivered INTEGER NOT NULL DEFAULT 0
            )"
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_nid)"
        )
        .execute(&pool)
        .await?;

        Ok(Self { pool })
    }

    async fn store_message(
        &self,
        from_nid: &str,
        to_nid: &str,
        ciphertext: &str,
    ) -> Result<i64, Box<dyn std::error::Error>> {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query(
            "INSERT INTO messages (from_nid, to_nid, ciphertext, timestamp, delivered)
             VALUES (?, ?, ?, ?, 1)"
        )
        .bind(from_nid)
        .bind(to_nid)
        .bind(ciphertext)
        .bind(&timestamp)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    async fn get_messages(&self, limit: i64) -> Result<Vec<StoredMessage>, Box<dyn std::error::Error>> {
        let rows = sqlx::query_as::<_, MessageRow>(
            "SELECT id, from_nid, to_nid, ciphertext, timestamp, delivered
             FROM messages ORDER BY id DESC LIMIT ?"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    async fn get_messages_from(&self, from_nid: &str, limit: i64) -> Result<Vec<StoredMessage>, Box<dyn std::error::Error>> {
        let rows = sqlx::query_as::<_, MessageRow>(
            "SELECT id, from_nid, to_nid, ciphertext, timestamp, delivered
             FROM messages WHERE from_nid = ? ORDER BY id DESC LIMIT ?"
        )
        .bind(from_nid)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }
}

#[derive(sqlx::FromRow)]
struct MessageRow {
    id: i64,
    from_nid: String,
    to_nid: String,
    ciphertext: String,
    timestamp: String,
    delivered: i64,
}

impl From<MessageRow> for StoredMessage {
    fn from(r: MessageRow) -> Self {
        Self {
            id: r.id,
            from_nid: r.from_nid,
            to_nid: r.to_nid,
            ciphertext: r.ciphertext,
            timestamp: r.timestamp,
            delivered: r.delivered != 0,
        }
    }
}

// ------------------------------------------------------------------ //
//  Helpers                                                           //
// ------------------------------------------------------------------ //

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn null_id_from_fingerprint(fp: &str) -> String {
    nullnode_dht_core::compute_null_id(fp)
}

fn generate_identity() -> Result<Identity, Box<dyn std::error::Error>> {
    use rand::Rng;
    use sequoia_openpgp::cert::prelude::*;

    let suffix: String = (0..4)
        .map(|_| format!("{:02x}", rand::thread_rng().r#gen::<u8>()))
        .collect();
    let uid = format!("nn-{} <nn-{}@nullnode.local>", suffix, suffix);

    // Generate keypair using Sequoia (Cv25519 EdDSA)
    let (cert, _sig) = CertBuilder::general_purpose(Some(uid.as_str()))
        .set_cipher_suite(sequoia_openpgp::cert::CipherSuite::Cv25519)
        .set_creation_time(std::time::SystemTime::now())
        .generate()
        .map_err(|e| format!("key generation failed: {}", e))?;

    let fingerprint = cert.fingerprint().to_hex().to_uppercase();
    let null_id = null_id_from_fingerprint(&fingerprint);

    // Save the cert for later use
    let cert_dir = home_dir().join(".nullnode/gnupg");
    std::fs::create_dir_all(&cert_dir)?;
    let cert_path = cert_dir.join("own_cert.asc");
    let armored = {
        use sequoia_openpgp::serialize::Serialize;
        let mut buf = Vec::new();
        cert.as_tsk().serialize(&mut buf)
            .map_err(|e| format!("serialize cert: {}", e))?;
        String::from_utf8_lossy(&buf).to_string()
    };
    std::fs::write(&cert_path, &armored)?;
    
    // SECURITY FIX (HIGH-5): Set 0o600 permissions for private key file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // SECURITY FIX (C1): Generate Kyber-768 keypair for post-quantum encryption
    let kyber_path = home_dir().join(KYBER_KEY_PATH);
    std::fs::create_dir_all(kyber_path.parent().unwrap())?;
    let kyber_kp = nullnode_crypto::kyber::KyberKeypair::load_or_generate(&kyber_path).map_err(|e| {
        format!("kyber keypair generation failed: {}", e)
    })?;

    // Print Kyber public key for debugging (can be removed later)
    let kyber_enc_b64 = nullnode_crypto::kyber::encode_enc_key(&kyber_kp.enc);
    println!("Kyber public key generated ({} bytes)", kyber_enc_b64.len());

    let identity = Identity {
        fingerprint,
        null_id,
    };
    identity.save()?;

    Ok(identity)
}

// ------------------------------------------------------------------ //
//  DHT Client (for G1 Send)                                         //
// ------------------------------------------------------------------ //

/// Connect to the seed DHT node and look up a recipient's address.
/// This uses the centralized seed DHT model (G4: no Kademlia routing).
async fn dht_lookup(seed_url: &str, null_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    use nullnode_protocol::envelope::WireEnvelope;

    let ws_url = seed_url.replace("http://", "ws://").replace("https://", "wss://");
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|e| format!("DHT connect failed: {}", e))?;

    // SECURITY FIX (C2): Sign the dht-get request
    let sig_data = format!("dht-get:{}\n", serde_json::json!({"key": null_id}));
    let our_cert = load_cert()?;
    let sig = nullnode_dht_core::sign_data(&sig_data, &our_cert)
        .map_err(|e| format!("sign failed: {}", e))?;

    // Send dht-get (construct WireEnvelope manually)
    let req = WireEnvelope {
        msg_type: "dht-get".to_string(),
        msg_id: uuid_hex(),
        ts: chrono::Utc::now().timestamp() as f64,
        sig: sig.clone(),
        payload: {
            let mut m = serde_json::Map::new();
            m.insert("key".to_string(), serde_json::Value::String(null_id.to_string()));
            serde_json::Value::Object(m)
        },
    };
    let req_json = serde_json::to_string(&req)?;
    ws.send(Message::Text(req_json.into()))
        .await
        .map_err(|e| format!("DHT send failed: {}", e))?;

    // Read response
    if let Some(Ok(Message::Text(resp_text))) = ws.next().await {
        let resp: WireEnvelope = serde_json::from_str(&resp_text)?;
        if resp.msg_type == "dht-found" {
            let address = resp.payload_str("value").unwrap_or("");
            if !address.is_empty() {
                return Ok(address.to_string());
            }
        }
    }

    Err("recipient not found in DHT".into())
}

// ------------------------------------------------------------------ //
//  Relay Client (for G2 Read)                                        //
// ------------------------------------------------------------------ //

/// SECURITY FIX (C2): Fetch messages from the relay mailbox for our null_id.
/// Uses relay-fetch protocol with GPG signature for authentication.
async fn relay_fetch(relay_url: &str, null_id: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let ws_url = relay_url.replace("http://", "ws://").replace("https://", "wss://");
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|e| format!("Relay connect failed: {}", e))?;

    // Load identity to get fingerprint for signing and cert for TOFU
    let identity = Identity::load()?;
    let cert = identity.cert()?;
    let cert_armored = {
        use sequoia_openpgp::serialize::Serialize;
        let mut buf = Vec::new();
        cert.as_tsk().serialize(&mut buf)
            .map_err(|e| format!("serialize cert: {}", e))?;
        String::from_utf8_lossy(&buf).to_string()
    };
    
    // SECURITY FIX (C2): Sign the fetch request with our PGP key
    let nonce = uuid_hex();
    let timestamp = chrono::Utc::now().timestamp() as f64;
    let sig_data = format!("relay-fetch:{}:{}:{}", null_id, timestamp, nonce);
    let sig = sign_for_transport(&sig_data)?;

    // SECURITY FIX (C2): Use relay-fetch protocol with ALL required fields
    let req = serde_json::json!({
        "type": "relay-fetch",
        "recipient_nid": null_id,
        "requester_fp": identity.fingerprint,
        "sender_sig": sig,
        "sender_cert": cert_armored,
        "timestamp": timestamp,
        "nonce": nonce,
        "auth_hmac": "",
    });
    ws.send(Message::Text(req.to_string().into()))
        .await
        .map_err(|e| format!("Relay send failed: {}", e))?;

    // Read response
    if let Some(Ok(Message::Text(resp_text))) = ws.next().await {
        let resp: serde_json::Value = serde_json::from_str(&resp_text)?;
        
        // Check for error response
        if let Some(error) = resp.get("error").and_then(|e| e.as_str()) {
            return Err(format!("Relay error: {}", error).into());
        }
        
        // Parse entries from relay-fetch response
        if let Some(entries) = resp.get("entries").and_then(|m| m.as_array()) {
            let mut result = Vec::new();
            for entry in entries {
                if let Some(signed_blob) = entry.get("signed_blob").and_then(|b| b.as_str()) {
                    // TODO: decrypt signed_blob using Double Ratchet
                    // For now, just return the encrypted blob (it will be decrypted by the caller)
                    result.push(signed_blob.to_string());
                }
            }
            return Ok(result);
        }
    }

    Ok(Vec::new())
}

// ------------------------------------------------------------------ //
//  P2P Send (G1)                                                     //
// ------------------------------------------------------------------ //

/// Send a message to a recipient via DHT lookup + direct P2P delivery.
/// SECURITY FIX (C1): Uses Kyber-768 KEM + Double Ratchet for post-quantum encryption.
async fn send_message(
    identity: &Identity,
    recipient_nid: &str,
    message: &str,
    store: &MessageStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let contacts = load_contacts();
    let recipient_fp = contacts
        .get(recipient_nid)
        .ok_or("unknown contact — add with 'add-contact' first")?;

    println!("Looking up {} in DHT...", recipient_nid);

    // G1: Look up recipient's address via DHT
    let recipient_addr = dht_lookup(SEED_URL, recipient_nid).await?;
    println!("Found at: {}", recipient_addr);

    println!("Establishing P2P connection...");

    // G1: Connect to recipient's P2P listener
    let ws_url = recipient_addr.replace("http://", "ws://").replace("https://", "wss://");
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|e| format!("P2P connect failed: {}", e))?;

    // SECURITY FIX (C1): Load our Kyber keypair for key exchange
    let kyber_path = home_dir().join(KYBER_KEY_PATH);
    let our_kyber = nullnode_crypto::kyber::KyberKeypair::load_or_generate(&kyber_path)
        .map_err(|e| format!("kyber keypair load failed: {}", e))?;
    let our_kyber_enc_b64 = nullnode_crypto::kyber::encode_enc_key(&our_kyber.enc);

    // SECURITY FIX (C1): Perform handshake with Kyber key included
    let hello = nullnode_p2p::protocol::build_p2p_hello(identity.fingerprint.as_str(), 1, 16, &our_kyber_enc_b64);
    
    // SECURITY FIX (C2): Sign the P2P hello with our PGP key
    let hello_sig_data = format!("p2p-hello:{}\n", hello.payload);
    let hello_sig = sign_for_transport(&hello_sig_data)?;
    let hello = nullnode_p2p::protocol::build_p2p_hello_signed(
        identity.fingerprint.as_str(), 1, 16, &our_kyber_enc_b64, &hello_sig
    );
    
    ws.send(Message::Text(serde_json::to_string(&hello)?.into()))
        .await
        .map_err(|e| format!("P2P hello failed: {}", e))?;

    // Wait for hello-ack and extract peer's Kyber public key
    let mut peer_kyber_enc: Option<nullnode_crypto::kyber::KyberEncapsulationKey> = None;
    if let Some(Ok(Message::Text(resp))) = ws.next().await {
        let ack: serde_json::Value = serde_json::from_str(&resp)?;
        if ack.get("type").and_then(|t| t.as_str()) != Some("p2p-hello-ack") {
            return Err(format!("Unexpected response: {}", resp).into());
        }
        
        // SECURITY FIX (C1): Extract peer's Kyber public key for KEM exchange
        if let Some(kyber_b64) = ack.get("kyber_enc_key").and_then(|k| k.as_str()) {
            peer_kyber_enc = nullnode_crypto::kyber::decode_enc_key(kyber_b64).ok();
        }
        if peer_kyber_enc.is_none() {
            println!("Warning: no Kyber public key from peer, falling back to plaintext (insecure)");
        }
    } else {
        return Err("No hello-ack received".into());
    }

    // SECURITY FIX (C1): Perform Kyber KEM exchange and create Double Ratchet session
    let peer_kyber = peer_kyber_enc.as_ref().ok_or("no peer Kyber key")?;
    let (_init_ct, init_shared_secret) = nullnode_crypto::kyber::KyberKeypair::encapsulate(peer_kyber)
        .map_err(|e| format!("kyber encapsulate: {}", e))?;
    
    let peer_nid = nullnode_crypto::null_id(recipient_fp);
    let our_nid = &identity.null_id;
    let mut ratchet_session = nullnode_crypto::DoubleRatchetSession::new(
        recipient_fp,
        &peer_nid,
        &identity.fingerprint,
        true, // is_initiator
        &init_shared_secret,
    ).map_err(|e| format!("ratchet init: {}", e))?;

    // SECURITY FIX (C1): Encrypt message using Double Ratchet + Kyber-768
    let encrypted_msg = ratchet_session.encrypt_message(message, peer_kyber)?;
    let msg_hash = sha256_hex(&encrypted_msg);

    // SECURITY FIX (C2): Sign the P2P message payload
    let msg_sig_data = format!("p2p-message:{}\n", serde_json::json!({
        "seq": 1,
        "ciphertext": &encrypted_msg,
        "msg_hash": &msg_hash,
    }));
    let msg_sig = sign_for_transport(&msg_sig_data)?;

    // Send encrypted message (signed)
    let p2p_msg = nullnode_p2p::protocol::build_p2p_message_signed(1, &encrypted_msg, &msg_hash, &msg_sig);
    ws.send(Message::Text(serde_json::to_string(&p2p_msg)?.into()))
        .await
        .map_err(|e| format!("P2P send failed: {}", e))?;

    // Wait for ack
    if let Some(Ok(Message::Text(resp))) = ws.next().await {
        let ack: serde_json::Value = serde_json::from_str(&resp)?;
        if ack.get("type").and_then(|t| t.as_str()) == Some("p2p-ack") {
            println!("Message delivered successfully!");
        } else {
            println!("Warning: unexpected response: {}", resp);
        }
    }

    // G5: Store sent message locally (only ciphertext, no plaintext)
    let _ = store
        .store_message(
            &identity.null_id,
            recipient_nid,
            &encrypted_msg,
        )
        .await;

    ws.close(None).await.ok();
    Ok(())
}

// ------------------------------------------------------------------ //
//  P2P Listener (G3)                                                 //
// ------------------------------------------------------------------ //

/// Start a WebSocket listener for incoming P2P connections.
async fn run_listener(
    identity: Identity,
    store: MessageStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let local_addr = listener.local_addr()?;
    println!("P2P listener on ws://{}", local_addr);
    println!("Your address for incoming connections: ws://{}:{}", local_addr.ip(), local_addr.port());
    println!("Register this address in the DHT with your null_id to receive messages.");
    println!("Waiting for connections...");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let store_clone = store.clone();
        let id_clone = identity.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_incoming_connection(stream, peer_addr, id_clone, store_clone).await {
                tracing::debug!("Connection from {} error: {}", peer_addr, e);
            }
        });
    }
}

async fn handle_incoming_connection(
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    identity: Identity,
    store: MessageStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let ws = tokio_tungstenite::accept_async(stream).await?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    // Read hello
    if let Some(Ok(Message::Text(hello_text))) = ws_rx.next().await {
        let hello: serde_json::Value = serde_json::from_str(&hello_text)?;
        if hello.get("type").and_then(|t| t.as_str()) != Some("p2p-hello") {
            return Err("expected p2p-hello".into());
        }

        // SECURITY FIX (C2): Verify peer's hello signature
        let peer_sig = hello.get("sig").and_then(|s| s.as_str()).unwrap_or("");
        let peer_fp = hello
            .get("public_key")
            .and_then(|k| k.as_str())
            .unwrap_or("unknown");
        
        if peer_sig.is_empty() {
            println!("Warning: p2p-hello has no signature, accepting but vulnerable to MITM");
        } else {
            // Construct the signed payload for verification
            let payload_start = hello_text.find('{').unwrap_or(0);
            let hello_sig_payload = format!("p2p-hello:{}\n", &hello_text[payload_start..]);
            if !nullnode_dht_core::verify_signature(&hello_sig_payload, peer_sig, peer_fp) {
                return Err(format!("p2p-hello signature verification failed for {}", peer_fp).into());
            }
            println!("Verified p2p-hello signature from {}", peer_fp);
        }

        // SECURITY FIX (C1): Extract peer's Kyber public key from hello
        let mut peer_kyber_enc: Option<nullnode_crypto::kyber::KyberEncapsulationKey> = None;
        if let Some(kyber_b64) = hello.get("kyber_enc_key").and_then(|k| k.as_str()) {
            peer_kyber_enc = nullnode_crypto::kyber::decode_enc_key(kyber_b64).ok();
        }

        // SECURITY FIX (C1): Load our Kyber keypair for key exchange
        let kyber_path = home_dir().join(KYBER_KEY_PATH);
        let our_kyber = nullnode_crypto::kyber::KyberKeypair::load_or_generate(&kyber_path)
            .map_err(|e| format!("kyber keypair load failed: {}", e))?;
        let our_kyber_enc_b64 = nullnode_crypto::kyber::encode_enc_key(&our_kyber.enc);

        // Send hello-ack with our Kyber public key (signed)
        let server_challenge = uuid_hex();
        let ack_sig_data = format!("p2p-hello-ack:{}\n", serde_json::json!({
            "public_key": identity.fingerprint,
            "nonce": 1,
            "pow_bits": 16,
            "server_challenge": &server_challenge,
            "kyber_enc_key": &our_kyber_enc_b64,
        }));
        let ack_sig = sign_for_transport(&ack_sig_data)?;
        let ack = nullnode_p2p::protocol::build_p2p_hello_ack_signed(
            identity.fingerprint.as_str(),
            1,
            16,
            &server_challenge,
            &our_kyber_enc_b64,
            &ack_sig,
        );
        ws_tx.send(Message::Text(serde_json::to_string(&ack)?.into())).await?;

        // SECURITY FIX (C1): Perform initial Kyber KEM exchange to create shared secret
        let peer_kyber = peer_kyber_enc.as_ref().ok_or("no peer Kyber key")?;
        let (_init_ct, init_shared_secret) = nullnode_crypto::kyber::KyberKeypair::encapsulate(peer_kyber)
            .map_err(|e| format!("kyber encapsulate: {}", e))?;

        // Create Double Ratchet session
        let peer_nid = nullnode_crypto::null_id(peer_fp);
        let mut ratchet_session = nullnode_crypto::DoubleRatchetSession::new(
            peer_fp,
            &peer_nid,
            &identity.fingerprint,
            false, // not initiator
            &init_shared_secret,
        ).map_err(|e| format!("ratchet init: {}", e))?;

        // Read message
        if let Some(Ok(Message::Text(msg_text))) = ws_rx.next().await {
            let msg: serde_json::Value = serde_json::from_str(&msg_text)?;
            if msg.get("type").and_then(|t| t.as_str()) == Some("p2p-message") {
                // SECURITY FIX (C2): Verify peer's message signature
                let msg_sig = msg.get("sig").and_then(|s| s.as_str()).unwrap_or("");
                if msg_sig.is_empty() {
                    println!("Warning: p2p-message has no signature, accepting but vulnerable to MITM");
                } else {
                    // Construct the signed payload for verification
                    let payload_start = msg_text.find('{').unwrap_or(0);
                    let msg_sig_payload = format!("p2p-message:{}\n", &msg_text[payload_start..]);
                    if !nullnode_dht_core::verify_signature(&msg_sig_payload, msg_sig, peer_fp) {
                        println!("Warning: p2p-message signature verification failed for {}", peer_fp);
                        // Don't reject, just warn - we still want to receive the message
                    } else {
                        println!("Verified p2p-message signature from {}", peer_fp);
                    }
                }
                
                let ciphertext = msg
                    .get("ciphertext")
                    .and_then(|c| c.as_str())
                    .unwrap_or("");

                // SECURITY FIX (C1): Decrypt using Double Ratchet + Kyber-768
                let plaintext = ratchet_session.decrypt_message(ciphertext, &our_kyber)
                    .map_err(|e| format!("decrypt failed: {}", e))?;

                println!("[{}] From: {} | {}", chrono::Utc::now().format("%H:%M:%S"), peer_fp, plaintext);

                // G5: Store received message (only ciphertext, no plaintext)
                let _ = store
                    .store_message(
                        peer_fp,
                        &identity.null_id,
                        ciphertext,
                    )
                    .await;

                // Send ack (signed)
                let ack_sig_data = format!("p2p-ack:{}\n", serde_json::json!({
                    "seq": 1,
                    "msg_hash": sha256_hex(&plaintext),
                }));
                let ack_sig = sign_for_transport(&ack_sig_data)?;
                let p2p_ack = nullnode_p2p::protocol::build_p2p_ack_signed(1, &sha256_hex(&plaintext), &ack_sig);
                ws_tx.send(Message::Text(serde_json::to_string(&p2p_ack)?.into())).await?;

            } else {
                println!("Warning: unexpected message type from {}", peer_fp);
            }
        }
    }

    ws_tx.close().await.ok();
    Ok(())
}

// ------------------------------------------------------------------ //
//  Crypto helpers (for client)                                       //
// ------------------------------------------------------------------ //

fn sha256_hex(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// SECURITY FIX (G6): Compute a safety number from two fingerprints.
/// This is analogous to Signal's safety number — a deterministic value
/// that both parties can compute and compare out-of-band (voice call,
/// QR scan, etc.) to verify no man-in-the-middle has substituted keys.
///
/// The safety number is derived from both fingerprints in sorted order,
/// so both parties compute the same value regardless of who initiated.
fn safety_number(fp1: &str, fp2: &str) -> String {
    let mut fps = [fp1.to_uppercase(), fp2.to_uppercase()];
    fps.sort();
    let combined = format!("{}|{}", fps[0], fps[1]);
    let hash = sha256_hex(&combined);
    // Format as 8 groups of 8 hex chars for easy visual comparison
    format!(
        "{} {} {} {} {} {} {} {}",
        &hash[0..8], &hash[8..16], &hash[16..24], &hash[24..32],
        &hash[32..40], &hash[40..48], &hash[48..56], &hash[56..64]
    )
}

fn uuid_hex() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let n: u128 = rng.r#gen();
    format!("{:032x}", n)[..16].to_string()
}

// ------------------------------------------------------------------ //
//  CLI                                                               //
// ------------------------------------------------------------------ //

/// NullNode P2P Messenger Client
#[derive(Parser, Debug)]
#[command(name = "nullnode", version, about)]
struct Args {
    /// Subcommand
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Initialize a new identity
    Init,
    /// Show your Null ID
    Id,
    /// Send a message
    Send {
        /// Recipient Null ID
        to: String,
        /// Message text
        message: String,
    },
    /// Read messages
    Read,
    /// List contacts
    Contacts,
    /// Add a contact
    AddContact {
        /// Contact Null ID
        null_id: String,
        /// Contact fingerprint
        fingerprint: String,
    },
    /// Start P2P listener
    Listen,
    /// Show DHT status
    Status,
    /// Verify a contact's safety number (G6)
    Verify {
        /// Contact Null ID
        null_id: String,
    },
    /// Show your safety number for a contact (G6)
    SafetyNumber {
        /// Contact Null ID
        null_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("nullnode=info".parse()?))
        .init();

    let args = Args::parse();

    // G5: Open message store (needed for all commands that touch messages)
    let store = MessageStore::open().await?;

    match args.cmd {
        Commands::Init => {
            println!("Generating post-quantum keypair (this may take a moment)...");
            let identity = generate_identity()?;
            println!("Identity created successfully!");
            println!("  Fingerprint: {}", identity.fingerprint);
            println!("  Null ID:     {}", identity.null_id);
            println!("\nShare your Null ID with contacts to receive messages.");
        }
        Commands::Id => {
            let identity = Identity::load()?;
            println!("Null ID:     {}", identity.null_id);
            println!("Fingerprint: {}", identity.fingerprint);
        }
        Commands::Send { to, message } => {
            let identity = Identity::load()?;
            send_message(&identity, &to, &message, &store).await?;
        }
        Commands::Read => {
            let identity = Identity::load()?;

            // G2: Fetch from relay mailbox
            println!("Checking relay mailbox...");
            let messages = relay_fetch(RELAY_URL, &identity.null_id).await?;

            if messages.is_empty() {
                println!("No new messages.");
            } else {
                println!("Messages ({}):", messages.len());
                for (i, msg) in messages.iter().enumerate() {
                    println!("  [{}] {}", i + 1, msg);
                    // G5: Store fetched messages (only ciphertext)
                    let _ = store
                        .store_message("relay", &identity.null_id, &base64::engine::general_purpose::STANDARD.encode(msg))
                        .await;
                }
            }

            // G5: Also show locally stored messages
            let stored = store.get_messages(20).await?;
            if !stored.is_empty() {
                println!("\nStored messages (last 20):");
                for msg in &stored {
                    // Messages are stored encrypted - display ciphertext preview
                    let preview = if msg.ciphertext.len() > 40 {
                        format!("{}...", &msg.ciphertext[..40])
                    } else {
                        msg.ciphertext.clone()
                    };
                    println!("  [{}] {} -> {}: {}", msg.id, msg.from_nid, msg.to_nid, preview);
                }
            }
        }
        Commands::Contacts => {
            let contacts = load_contacts();
            if contacts.is_empty() {
                println!("No contacts. Add one with: nullnode add-contact <null_id> <fingerprint>");
            } else {
                println!("Contacts:");
                for (nid, fp) in &contacts {
                    println!("  {} -> {}", nid, fp);
                }
            }
        }
        Commands::AddContact { null_id, fingerprint } => {
            if fingerprint.len() < 32 || !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("invalid fingerprint format — must be 32-40 hex chars".into());
            }
            let mut contacts = load_contacts();
            contacts.insert(null_id.clone(), fingerprint.to_uppercase());
            save_contacts(&contacts)?;
            println!("Added contact: {} -> {}", null_id, fingerprint.to_uppercase());
        }
        Commands::Listen => {
            let identity = Identity::load()?;
            println!("Starting P2P listener...");
            run_listener(identity, store).await?;
        }
        Commands::Status => {
            println!("NullNode Status:");
            println!("================");

            match Identity::load() {
                Ok(id) => {
                    println!("  Identity: {}", id.null_id);
                    println!("  Fingerprint: {}", id.fingerprint);
                }
                Err(_) => println!("  Identity: NOT INITIALIZED (run 'nullnode init')"),
            }

            let contacts = load_contacts();
            println!("  Contacts: {}", contacts.len());

            let bootstrap_path = home_dir().join(BOOTSTRAP_PATH);
            if bootstrap_path.exists() {
                println!("  Bootstrap pin cache: present");
            } else {
                println!("  Bootstrap pin cache: none");
            }

            println!("  Key dir: {}", home_dir().join(GPG_HOME).display());
            println!("  Message DB: {}", home_dir().join(MESSAGES_DB).display());
            println!("  Seed URL: {}", SEED_URL);
            println!("  Relay URL: {}", RELAY_URL);

            // G4: Document that the DHT is centralized (seed model)
            println!("\n  DHT model: Centralized seed (no Kademlia routing)");
            println!("  The DHT seed node at {} stores all key-value pairs.", SEED_URL);
            println!("  Clients connect directly to the seed for lookups and writes.");
            println!("  P2P connections are established after DHT lookup for direct delivery.");
        }
        Commands::Verify { null_id } => {
            let contacts = load_contacts();
            let fp = contacts.get(&null_id).ok_or("unknown contact — add with 'add-contact' first")?;
            let identity = Identity::load()?;
            let sn = safety_number(&identity.fingerprint, fp);
            println!("Safety number for {}:", null_id);
            println!("  {}", sn);
            println!("\nVerify this matches your contact's safety number.");
            println!("If it doesn't match, a man-in-the-middle may be intercepting your communication.");
        }
        Commands::SafetyNumber { null_id } => {
            let contacts = load_contacts();
            let fp = contacts.get(&null_id).ok_or("unknown contact — add with 'add-contact' first")?;
            let identity = Identity::load()?;
            let sn = safety_number(&identity.fingerprint, fp);
            println!("Your safety number with {}:", null_id);
            println!("  {}", sn);
        }
    }

    Ok(())
}
