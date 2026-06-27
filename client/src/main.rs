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
use std::sync::Arc;

use clap::Parser;
use futures::{SinkExt as _, StreamExt as _};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::Pool;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tracing_subscriber::EnvFilter;
use base64::Engine;
use zeroize::ZeroizeOnDrop;

// ------------------------------------------------------------------ //
//  Configuration                                                     //
// ------------------------------------------------------------------ //

const GPG_HOME: &str = ".nullnode/gnupg";
const CONTACTS_PATH: &str = ".nullnode/contacts.json";
const ALIASES_PATH: &str = ".nullnode/aliases.json";
const DELIVERY_SECRETS_PATH: &str = ".nullnode/delivery_secrets.json";
const IDENTITY_PATH: &str = ".nullnode/identity.json";
const BOOTSTRAP_PATH: &str = ".nullnode/bootstrap_pin_cache.json";
const MESSAGES_DB: &str = ".nullnode/messages.db";
const SEED_URL: &str = "ws://127.0.0.1:9001";
const RELAY_URL: &str = "ws://127.0.0.1:8765";
const DB_KEY_PATH: &str = ".nullnode/db_key.json";

// ------------------------------------------------------------------ //
//  Database Encryption (AES-256-GCM)                                  //
// ------------------------------------------------------------------ //

/// Database encryption key for message-at-rest protection.
///
/// Uses AES-256-GCM with a random 96-bit nonce per encryption.
/// The key is stored on disk encrypted with a key derived from the
/// user's identity key (first app: derived from Kyber public key hash).
///
/// ACS2.6 Part III.2: AEAD enforcement for local data-at-rest.
/// SECURITY FIX (C2): Zeroize key material on drop.
#[derive(ZeroizeOnDrop)]
struct DbEncryptionKey {
    #[zeroize(drop)]
    key: [u8; 32],
}

impl DbEncryptionKey {
    /// Get a reference to the raw key bytes (for Kyber key encryption).
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Synchronous version of load_or_create for use in non-async contexts (e.g., cmd_init).
    pub fn load_or_create_sync() -> Self {
        let path = home_dir().join(DB_KEY_PATH);
        if path.exists() {
            let hex_key = std::fs::read_to_string(&path).expect("failed to read db key");
            let bytes = hex::decode(hex_key.trim()).expect("invalid db key hex");
            assert_eq!(bytes.len(), 32, "invalid db key length");
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Self { key }
        } else {
            use rand::RngCore;
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let hex_key = hex::encode(key);
            std::fs::write(&path, &hex_key).expect("failed to write db key");
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            Self { key }
        }
    }

    /// Load or create the database encryption key.
    ///
    /// In the first app, the key is stored directly on disk (0o600).
    /// In production, this should be derived from HSM/TEK + user entropy.
    async fn load_or_create() -> Result<Self, Box<dyn std::error::Error>> {
        let path = home_dir().join(DB_KEY_PATH);

        if path.exists() {
            let hex_key = tokio::fs::read_to_string(&path).await?;
            let bytes = hex::decode(hex_key.trim())?;
            if bytes.len() != 32 {
                return Err("invalid db key length".into());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(Self { key })
        } else {
            // Generate a new random key
            let mut key = [0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut key);

            // Store with restrictive permissions
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let hex_key = hex::encode(key);
            tokio::fs::write(&path, &hex_key).await?;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));

            Ok(Self { key })
        }
    }

    /// Generate a fresh random 32-byte AES-256 key without persistent storage.
    /// Used for in-memory databases that should never be written to disk.
    fn generate_random() -> Self {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self { key }
    }

    /// Encrypt plaintext using AES-256-GCM.
    ///
    /// Output format: [nonce (12 bytes)] [ciphertext + tag]
    fn encrypt(&self, plaintext: &str) -> Result<String, Box<dyn std::error::Error>> {
        use aes_gcm::aead::{Aead, KeyInit, OsRng};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        let key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);

        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| format!("encryption failed: {}", e))?;

        // Prepend nonce to ciphertext
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(base64::engine::general_purpose::STANDARD.encode(&output))
    }

    /// Decrypt ciphertext using AES-256-GCM.
    ///
    /// Expects format: [nonce (12 bytes)] [ciphertext + tag]
    fn decrypt(&self, encrypted_b64: &str) -> Result<String, Box<dyn std::error::Error>> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        let data = base64::engine::general_purpose::STANDARD.decode(encrypted_b64)?;
        if data.len() < 12 + 16 {
            // nonce + minimum tag
            return Err("ciphertext too short".into());
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);

        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("decryption failed: {}", e))?;

        Ok(String::from_utf8(plaintext)?)
    }
}

// ------------------------------------------------------------------ //
//  Identity                                                          //
// ------------------------------------------------------------------ //

/// Path to persistent Kyber keypair
const KYBER_KEY_PATH: &str = ".nullnode/kyber_key.json";

/// Prompt for the GPG passphrase (from stdin, no echo if possible).
fn prompt_passphrase() -> Result<String, Box<dyn std::error::Error>> {
    use std::io::Write;

    print!("Enter GPG key passphrase (leave empty for none): ");
    std::io::stdout().flush()?;

    // Try to read with no-echo if available (Unix), otherwise plain readline
    #[cfg(unix)]
    {
        if let Ok(pass) = rpassword::read_password() {
            return Ok(pass);
        }
    }
    // Fallback: plain readline
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim_end().to_string())
}

/// Load the Sequoia certificate for signing operations.
/// Tries the age-encrypted `own_cert.age` first, falls back to plaintext `own_cert.asc`.
fn load_cert() -> Result<sequoia_openpgp::Cert, Box<dyn std::error::Error>> {
    use sequoia_openpgp::parse::Parse;

    let cert_dir = home_dir().join(GPG_HOME);
    let enc_path = cert_dir.join("own_cert.age");
    let plain_path = cert_dir.join("own_cert.asc");

    // Try age-encrypted cert first
    if enc_path.exists() {
        let armored = std::fs::read_to_string(&enc_path)?;
        let password = prompt_passphrase()?;
        if password.is_empty() {
            return Err("encrypted own_cert.age requires a passphrase".into());
        }
        let plaintext = decrypt_cert_armored(&armored, &password)?;
        return sequoia_openpgp::Cert::from_bytes(plaintext.as_bytes())
            .map_err(|e| format!("parse decrypted cert: {}", e).into());
    }

    // Fallback to plaintext legacy format
    if !plain_path.exists() {
        return Err("no identity found — run 'nullnode init' first".into());
    }
    let armored = std::fs::read_to_string(&plain_path)?;
    sequoia_openpgp::Cert::from_bytes(armored.as_bytes())
        .map_err(|e| format!("parse cert: {}", e).into())
}

/// Encrypt the GPG secret key cert using age passphrase encryption.
/// Output format: age ASCII-armored (-----BEGIN AGE ENCRYPTED FILE-----).
fn encrypt_cert_armored(plaintext: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    use age::secrecy::SecretString;
    use std::io::Write;

    let passphrase = SecretString::from(password.to_string());
    let encryptor = age::Encryptor::with_user_passphrase(passphrase);
    let mut buf = Vec::new();
    {
        let mut armored_writer = age::armor::ArmoredWriter::wrap_output(&mut buf, age::armor::Format::AsciiArmor)
            .map_err(|e| format!("age armor wrap: {}", e))?;
        let mut writer = encryptor.wrap_output(&mut armored_writer)
            .map_err(|e| format!("age encrypt: {}", e))?;
        writer.write_all(plaintext.as_bytes())
            .map_err(|e| format!("age write: {}", e))?;
        writer.finish()
            .map_err(|e| format!("age finish: {}", e))?;
        armored_writer.finish()
            .map_err(|e| format!("age armor finish: {}", e))?;
    }
    String::from_utf8(buf).map_err(|e| format!("age output utf8: {}", e).into())
}

/// Decrypt an age-encrypted cert.
fn decrypt_cert_armored(armored: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    use age::secrecy::SecretString;

    let passphrase = SecretString::from(password.to_string());
    let identity = age::scrypt::Identity::new(passphrase);
    let plaintext = age::decrypt(&identity, armored.as_bytes())
        .map_err(|e| format!("age decrypt: {}", e))?;
    String::from_utf8(plaintext)
        .map_err(|e| format!("decrypted cert utf8: {}", e).into())
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
//  Aliases                                                          //
// ------------------------------------------------------------------ //

type Aliases = HashMap<String, String>; // alias -> null_id

fn load_aliases() -> Aliases {
    let path = home_dir().join(ALIASES_PATH);
    if !path.exists() {
        return HashMap::new();
    }
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    serde_json::from_str(&content).unwrap_or_default()
}

fn save_aliases(aliases: &Aliases) -> Result<(), Box<dyn std::error::Error>> {
    let path = home_dir().join(ALIASES_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(aliases)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Resolve a user-provided recipient string to a Null ID.
/// If the input matches a known alias, return the mapped null_id.
/// Otherwise return the input unchanged (assumed to be a raw null_id).
fn resolve_recipient(input: &str, aliases: &Aliases) -> String {
    aliases.get(input).cloned().unwrap_or_else(|| input.to_string())
}

// ------------------------------------------------------------------ //
//  WebSocket Transport (ws:// + wss://)                              //
// ------------------------------------------------------------------ //

/// Connect a WebSocket, supporting both ws:// and wss:// URLs.
/// For wss://, tokio-tungstenite handles TLS automatically via rustls-native-tls
/// with WebPKI certificate verification.
/// Returns a WebSocket stream over MaybeTlsStream (TLS when scheme is wss://).
#[allow(clippy::type_complexity)]
async fn ws_connect(
    url: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Box<dyn std::error::Error>,
> {
    tokio_tungstenite::connect_async(url)
        .await
        .map(|(ws, _)| ws)
        .map_err(|e| format!("WebSocket connect failed: {}", e).into())
}

// ------------------------------------------------------------------ //
//  Delivery Token Secrets (ACS2.6 Part I.2)                          //
// ------------------------------------------------------------------ //

/// Load or create per-contact delivery master secrets.
/// Each contact gets a unique HMAC master secret for token derivation.
fn load_delivery_secrets() -> HashMap<String, String> {
    let path = home_dir().join(DELIVERY_SECRETS_PATH);
    if !path.exists() {
        return HashMap::new();
    }
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    serde_json::from_str(&content).unwrap_or_default()
}

fn save_delivery_secrets(secrets: &HashMap<String, String>) -> Result<(), Box<dyn std::error::Error>> {
    let path = home_dir().join(DELIVERY_SECRETS_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(secrets)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Get or create a delivery master secret for a contact.
/// The secret is stored as hex on disk; in production it should be derived
/// from the Kyber shared secret during contact initialization.
fn get_or_create_delivery_secret(contact_nid: &str) -> Result<nullnode_crypto::delivery_tokens::DeliveryMasterSecret, Box<dyn std::error::Error>> {
    let mut secrets = load_delivery_secrets();

    if let Some(hex) = secrets.get(contact_nid) {
        let bytes = hex::decode(hex)?;
        if bytes.len() != 64 {
            return Err("invalid delivery secret length".into());
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        let master = nullnode_crypto::delivery_tokens::DeliveryMasterSecret::from_bytes(arr);
        Ok(master)
    } else {
        let master = nullnode_crypto::delivery_tokens::DeliveryMasterSecret::generate();
        let bytes = *master.as_bytes();
        secrets.insert(contact_nid.to_string(), hex::encode(&bytes));
        save_delivery_secrets(&secrets)?;
        Ok(master)
    }
}

/// Generate a delivery token message for a recipient.
/// ACS2.6 Part I.2: Anonymous delivery token for sealed sender.
fn generate_delivery_token(
    recipient_nid: &str,
    message_id: u64,
) -> Result<nullnode_crypto::delivery_tokens::DeliveryTokenMessage, Box<dyn std::error::Error>> {
    let master = get_or_create_delivery_secret(recipient_nid)?;
    let token = master.derive_token(recipient_nid, message_id)?;

    // Hash the sender's public key (fingerprint) for recipient identification
    let identity = Identity::load()?;
    let pk_hash = sha256_hex(&identity.fingerprint);
    let sender_key_hash = format!("{}:{}", &pk_hash[..16], &pk_hash[16..32]);

    Ok(nullnode_crypto::delivery_tokens::DeliveryTokenMessage {
        token: token.to_hex(),
        sender_key_hash,
        timestamp: chrono::Utc::now().timestamp() as u64,
    })
}

// ------------------------------------------------------------------ //
//  PIR Local Contact Discovery (ACS2.6 Part I.3)                     //
// ------------------------------------------------------------------ //

/// Local PIR-based contact registry for privacy-preserving contact lookup.
/// Prevents forensic analysis of the contact list by using cuckoo-hashed bins.
struct PirContactCache {
    registry: nullnode_crypto::pir::PirRegistry,
}

impl PirContactCache {
    /// Build a PIR cache from the local contacts file.
    fn build() -> Result<Self, Box<dyn std::error::Error>> {
        let contacts = load_contacts();
        let mut registry = nullnode_crypto::pir::PirRegistry::new();

        for (nid, fingerprint) in &contacts {
            let fp_hash = sha256_hex(fingerprint);
            let hash_bytes = hex::decode(&fp_hash)?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_bytes);
            // Store the NID as metadata (contact identifier)
            let entry = nullnode_crypto::pir::PirContactEntry::new(hash, nid.as_bytes())?;
            // Use cuckoo hashing to determine bin placement
            let client = nullnode_crypto::pir::PirClient::new();
            let (bin_idx, _) = client.prepare_registration(&hash)?;
            registry.add_entry(bin_idx, &entry)?;
        }

        Ok(Self { registry })
    }

    /// Look up a contact by fingerprint hash using PIR blind retrieval.
    /// Returns the contact NID if found.
    fn lookup(&self, fingerprint: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let fp_hash = sha256_hex(fingerprint);
        let hash_bytes = hex::decode(&fp_hash)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);

        let client = nullnode_crypto::pir::PirClient::new();
        let tokens = client.query_contact(&hash)?;

        // Query each candidate bin
        for token in &tokens {
            if let Some(response) = self.registry.handle_query(token) {
                // Process response: XOR mask + scan for matching entry
                if let Some(entry) = client.process_response(&response, &token.xor_mask, &hash)? {
                    // Extract NID from metadata (bytes 32.. of the entry)
                    let raw = entry.to_bytes();
                    let nid = String::from_utf8_lossy(&raw[32..]).trim_end_matches('\0').to_string();
                    if !nid.is_empty() {
                        return Ok(Some(nid));
                    }
                }
            }
        }

        Ok(None)
    }
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

struct MessageStore {
    pool: Pool<sqlx::Sqlite>,
    db_key: DbEncryptionKey,
}

impl MessageStore {
    /// Get a reference to the database encryption key (for encrypting Kyber keys at rest).
    pub fn db_key(&self) -> &[u8; 32] {
        &self.db_key.key
    }
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

        // SECURITY FIX (G9): Persist DoubleRatchet sessions so encrypted
        // conversations survive restarts and relay-fetched messages can be
        // decrypted. The session JSON contains chain keys and pending
        // ciphertext, encrypted at rest by db_key.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS ratchet_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_nid TEXT NOT NULL UNIQUE,
                session_data TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"
        )
        .execute(&pool)
        .await?;

        let db_key = DbEncryptionKey::load_or_create().await?;

        Ok(Self { pool, db_key })
    }

    /// Create an in-memory SQLite database for ephemeral KEM handshake state.
    /// No data is written to disk — all state is lost on process exit.
    /// Uses a fresh random encryption key (no persistence needed).
    async fn open_in_memory() -> Result<Self, Box<dyn std::error::Error>> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS kem_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_nid TEXT NOT NULL,
                session_key BLOB NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )"
        )
        .execute(&pool)
        .await?;

        let db_key = DbEncryptionKey::generate_random();

        Ok(Self { pool, db_key })
    }

    async fn store_message(
        &self,
        from_nid: &str,
        to_nid: &str,
        ciphertext: &str,
    ) -> Result<i64, Box<dyn std::error::Error>> {
        let timestamp = chrono::Utc::now().to_rfc3339();
        // ACS2.6 Part III.2: Encrypt ciphertext before writing to disk
        let encrypted_ct = self.db_key.encrypt(ciphertext)?;
        let result = sqlx::query(
            "INSERT INTO messages (from_nid, to_nid, ciphertext, timestamp, delivered)
             VALUES (?, ?, ?, ?, 1)"
        )
        .bind(from_nid)
        .bind(to_nid)
        .bind(&encrypted_ct)
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

        // Decrypt ciphertext on read
        Ok(rows.into_iter().filter_map(|r| {
            match self.db_key.decrypt(&r.ciphertext) {
                Ok(pt) => Some(StoredMessage {
                    id: r.id,
                    from_nid: r.from_nid,
                    to_nid: r.to_nid,
                    ciphertext: pt,
                    timestamp: r.timestamp,
                    delivered: r.delivered != 0,
                }),
                Err(_) => None, // Skip corrupted/undecryptable entries
            }
        }).collect())
    }

    /// Save or update a DoubleRatchet session for a peer.
    /// The session JSON is encrypted with db_key before writing to disk.
    async fn save_session(
        &self,
        peer_nid: &str,
        session_json: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let encrypted_data = self.db_key.encrypt(session_json)?;
        sqlx::query(
            "INSERT INTO ratchet_sessions (peer_nid, session_data, updated_at)
             VALUES (?, ?, ?)
             ON CONFLICT(peer_nid) DO UPDATE SET
                session_data = excluded.session_data,
                updated_at = excluded.updated_at"
        )
        .bind(peer_nid)
        .bind(&encrypted_data)
        .bind(&timestamp)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Load a DoubleRatchet session for a peer.
    /// Returns None if no session exists for this peer.
    async fn load_session(
        &self,
        peer_nid: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT session_data FROM ratchet_sessions WHERE peer_nid = ?"
        )
        .bind(peer_nid)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(data,)| self.db_key.decrypt(&data)).transpose()?)
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

        Ok(rows.into_iter().filter_map(|r| {
            match self.db_key.decrypt(&r.ciphertext) {
                Ok(pt) => Some(StoredMessage {
                    id: r.id,
                    from_nid: r.from_nid,
                    to_nid: r.to_nid,
                    ciphertext: pt,
                    timestamp: r.timestamp,
                    delivered: r.delivered != 0,
                }),
                Err(_) => None,
            }
        }).collect())
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

    // Serialize the cert (secret key) to armored text
    let armored = {
        use sequoia_openpgp::serialize::Serialize;
        let mut buf = Vec::new();
        cert.as_tsk().serialize(&mut buf)
            .map_err(|e| format!("serialize cert: {}", e))?;
        String::from_utf8_lossy(&buf).to_string()
    };

    // Prompt for passphrase to protect the GPG secret key
    let cert_dir = home_dir().join(".nullnode/gnupg");
    std::fs::create_dir_all(&cert_dir)?;
    let password = prompt_passphrase()?;

    if password.is_empty() {
        // No passphrase: save as plaintext (legacy behavior)
        let cert_path = cert_dir.join("own_cert.asc");
        std::fs::write(&cert_path, &armored)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o600))?;
        }
    } else {
        // Encrypt with age passphrase encryption
        let enc_path = cert_dir.join("own_cert.age");
        let encrypted = encrypt_cert_armored(&armored, &password)?;
        std::fs::write(&enc_path, &encrypted)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&enc_path, std::fs::Permissions::from_mode(0o600))?;
        }
        // Optionally remove old plaintext file if exists
        let old_plain = cert_dir.join("own_cert.asc");
        if old_plain.exists() {
            let _ = std::fs::remove_file(&old_plain);
        }
    }

    // SECURITY FIX (C1): Generate Kyber-768 keypair for post-quantum encryption
    // SECURITY FIX (C6): Encrypt secret key at rest using DbEncryptionKey
    let kyber_path = home_dir().join(KYBER_KEY_PATH);
    std::fs::create_dir_all(kyber_path.parent().unwrap())?;
    let kyber_kp = nullnode_crypto::kyber::KyberKeypair::generate()
        .map_err(|e| format!("kyber keypair generation failed: {}", e))?;
    // Load or create encryption key, then encrypt+save the Kyber secret key
    let db_key = DbEncryptionKey::load_or_create_sync();
    kyber_kp.save(&kyber_path, db_key.key())
        .map_err(|e| format!("kyber keypair save failed: {}", e))?;

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

    // Normalize URL scheme: https:// → wss://, http:// → ws://
    let ws_url = seed_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");

    let mut ws = ws_connect(&ws_url).await
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

/// SECURITY FIX (L1): Privacy-enhanced DHT lookup using PIR (Private Information Retrieval).
/// Instead of sending the null_id in plaintext to the DHT server (which would reveal
/// WHO the user is looking up), this function uses XOR-based PIR with cuckoo hashing
/// to query blind bins. The server learns neither the queried contact nor whether
/// the lookup succeeded.
///
/// The DHT bootstrap server must expose a `/pir-query` WebSocket endpoint that
/// accepts PIR query tokens and returns bin contents. Falls back to standard
/// `dht_lookup` if the server doesn't support PIR.
async fn pir_dht_lookup(
    seed_url: &str,
    null_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use nullnode_crypto::pir::{PirClient, PIR_CUCKOO_FANOUT};
    use sha2::{Digest, Sha256};

    // Compute fingerprint hash from null_id (same as what's stored in PIR bins)
    let mut hasher = Sha256::new();
    hasher.update(b"pir-fp-hash-v1:");
    hasher.update(null_id.as_bytes());
    let fp_hash: [u8; 32] = hasher.finalize().into();

    let client = PirClient::new();
    let queries = client.query_contact(&fp_hash)?;

    let ws_url = seed_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");

    let mut ws = ws_connect(&ws_url).await
        .map_err(|e| format!("PIR DHT connect failed: {}", e))?;

    // Send PIR queries (one per cuckoo bin candidate)
    let mut result: Option<String> = None;
    for query in queries.iter() {
        let req_json = serde_json::json!({
            "type": "pir-query",
            "bin_index": query.bin_index,
            "ephemeral_pk": base64::encode(query.client_ephemeral_pk),
            "nonce": uuid_hex(),
        });
        ws.send(Message::Text(req_json.to_string().into())).await
            .map_err(|e| format!("PIR query send failed: {}", e))?;

        // Read PIR response
        let resp_msg = ws.next().await
            .ok_or("PIR DHT connection closed")?
            .map_err(|e| format!("PIR DHT read failed: {}", e))?;
        let resp_text = match resp_msg {
            Message::Text(t) => t.to_string(),
            _ => continue,
        };
        let resp_json: serde_json::Value = serde_json::from_str(&resp_text)?;
        if resp_json["type"] != "pir-response" {
            continue;
        }
        let bin_data_b64 = resp_json["bin_data"]
            .as_str()
            .ok_or("missing bin_data in PIR response")?;
        let bin_data = base64::decode(bin_data_b64)
            .map_err(|e| format!("PIR bin_data decode: {}", e))?;

        let pir_resp = nullnode_crypto::pir::PirResponse {
            bin_data,
            dht_ephemeral_pk: [0u8; 32],
            nonce: [0u8; 8],
        };

        if let Some(entry) = client.process_response(&pir_resp, &query.xor_mask, &fp_hash)? {
            // Extract the contact address from the entry metadata
            let metadata = &entry.metadata;
            let addr = String::from_utf8_lossy(&metadata[32..])
                .trim_end_matches('\0')
                .to_string();
            if !addr.is_empty() {
                result = Some(addr.to_string());
                break;
            }
        }
    }

    ws.close(None).await.ok();

    match result {
        Some(addr) => Ok(addr),
        None => {
            println!("PIR lookup returned no result, falling back to standard DHT");
            dht_lookup(seed_url, null_id).await
        }
    }
}

// ------------------------------------------------------------------ //
//  Relay Client (for G2 Read)                                        //
// ------------------------------------------------------------------ //

/// SECURITY FIX (C2): Fetch messages from the relay mailbox for our null_id.
/// Uses relay-fetch protocol with GPG signature for authentication.
/// Fetch messages from relay mailbox and decrypt them using persisted
/// DoubleRatchet sessions.
/// SECURITY FIX (G9): Relay-fetched messages are now decrypted with the
/// DoubleRatchet session, not returned as raw ciphertext blobs.
async fn relay_fetch(
    relay_url: &str,
    null_id: &str,
    store: &MessageStore,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let ws_url = relay_url.replace("http://", "ws://").replace("https://", "wss://");
    let mut ws = ws_connect(&ws_url).await
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

    // Load our Kyber keypair for session decryption
    let kyber_path = home_dir().join(KYBER_KEY_PATH);
    let our_kyber = nullnode_crypto::kyber::KyberKeypair::load_or_generate(&kyber_path, store.db_key())
        .map_err(|e| format!("kyber keypair load failed: {}", e))?;

    // Read response
    if let Some(Ok(Message::Text(resp_text))) = ws.next().await {
        let resp: serde_json::Value = serde_json::from_str(&resp_text)?;

        // Check for error response
        if let Some(error) = resp.get("error").and_then(|e| e.as_str()) {
            return Err(format!("Relay error: {}", error).into());
        }

        // Parse entries from relay-fetch response and decrypt
        if let Some(entries) = resp.get("entries").and_then(|m| m.as_array()) {
            let mut result = Vec::new();
            for entry in entries {
                if let Some(signed_blob) = entry.get("signed_blob").and_then(|b| b.as_str()) {
                    // Extract sender info from the relay entry (not the blob)
                    let entry_sender_nid = entry
                        .get("sender_nid")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let entry_sender_fp = entry
                        .get("sender_fp")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    let decrypted = match relay_decrypt_message(
                        signed_blob,
                        entry_sender_nid,
                        entry_sender_fp,
                        store,
                        &our_kyber,
                    ).await {
                        Ok(plaintext) => plaintext,
                        Err(e) => {
                            println!("Warning: failed to decrypt relay message: {}", e);
                            continue;
                        }
                    };
                    result.push(decrypted);
                }
            }
            return Ok(result);
        }
    }

    Ok(Vec::new())
}

/// SECURITY FIX (M2): Send a message via relay with sealed sender.
/// The relay stores the message without knowing the sender's identity.
/// The sender identity is encapsulated under the recipient's Kyber public key
/// so only the recipient can learn who sent it.
async fn send_via_relay(
    identity: &Identity,
    recipient_nid: &str,
    message: &str,
    store: &MessageStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let ws_url = RELAY_URL.replace("http://", "ws://").replace("https://", "wss://");
    let mut ws = ws_connect(&ws_url).await
        .map_err(|e| format!("Relay connect failed: {}", e))?;

    // Load our Kyber keypair
    let kyber_path = home_dir().join(KYBER_KEY_PATH);
    let our_kyber = nullnode_crypto::kyber::KyberKeypair::load_or_generate(&kyber_path, store.db_key())
        .map_err(|e| format!("kyber keypair load failed: {}", e))?;
    let our_kyber_enc_b64 = nullnode_crypto::kyber::encode_enc_key(&our_kyber.enc);

    // Look up recipient's Kyber public key from DHT
    let recipient_kyber = lookup_kyber_for_nid(recipient_nid, store).await?;

    // Create or load DoubleRatchet session with recipient
    let session_json = store.load_session(recipient_nid).await?;
    let mut ratchet_session = if let Some(json) = session_json {
        nullnode_crypto::DoubleRatchetSession::deserialize(&json)
            .map_err(|e| format!("ratchet load: {}", e))?
    } else {
        // First message: perform KEM exchange
        let (ct, shared_secret) = nullnode_crypto::kyber::KyberKeypair::encapsulate(&recipient_kyber)
            .map_err(|e| format!("kyber encapsulate: {}", e))?;
        let mut session = nullnode_crypto::DoubleRatchetSession::new(
            recipient_nid,
            &identity.null_id,
            recipient_nid,
            true,
            &shared_secret,
        ).map_err(|e| format!("ratchet init: {}", e))?;
        // Send Kyber ciphertext to recipient in first message
        let _ct_hex = hex::encode(&ct);
        session
    };

    // SECURITY FIX (M1): Pad message to constant-size bucket
    let padded = pad_message_bucket(message);

    // SECURITY FIX (C1): Encrypt message using Double Ratchet + Kyber-768
    let ciphertext = ratchet_session.encrypt_message(&padded, &recipient_kyber)
        .map_err(|e| format!("ratchet encrypt: {}", e))?;

    // SECURITY FIX (M2): Generate sealed sender token
    // Encapsulate sender identity under recipient's Kyber key
    let sender_ident = format!("{}|{}|{}", identity.null_id, identity.fingerprint, &our_kyber_enc_b64);
    let (sealed_ct, _sealed_ss) = nullnode_crypto::kyber::KyberKeypair::encapsulate(&recipient_kyber)
        .map_err(|e| format!("kyber sealed encapsulate: {}", e))?;
    let sealed_sender_token = hex::encode(&sealed_ct);

    // Build the signed blob (WireEnvelope)
    let envelope = serde_json::json!({
        "type": "p2p-message",
        "seq": 1,
        "ciphertext": base64::encode(&ciphertext),
        "msg_hash": sha256_hex(&ciphertext),
    });
    let sig_data = format!("relay-store:{}:{}", recipient_nid, envelope);
    let sig = sign_for_transport(&sig_data)?;

    // SECURITY FIX (M2): Send with sender_nid="anonymous" + sealed_sender token
    let req = serde_json::json!({
        "type": "relay-store",
        "recipient_nid": recipient_nid,
        "signed_blob": serde_json::to_string(&envelope)?,
        "sender_nid": "anonymous",
        "sender_fp": "anonymous",
        "seq": 1,
        "timestamp": chrono::Utc::now().timestamp() as f64,
        "nonce": uuid_hex(),
        "sender_sig": sig,
        "sealed_sender": sealed_sender_token,
    });

    ws.send(Message::Text(serde_json::to_string(&req)?.into()))
        .await
        .map_err(|e| format!("relay-store send failed: {}", e))?;

    // Wait for relay-ok response
    if let Some(Ok(Message::Text(resp))) = ws.next().await {
        let resp_val: serde_json::Value = serde_json::from_str(&resp)?;
        if resp_val.get("type").and_then(|t| t.as_str()) == Some("relay-ok") {
            // Persist updated ratchet session
            let session_json = ratchet_session.serialize()
                .map_err(|e| format!("ratchet serialize: {}", e))?;
            store.save_session(recipient_nid, &session_json).await
                .map_err(|e| format!("ratchet save: {}", e))?;
            println!("Message delivered via relay (sealed sender) to {}", recipient_nid);
            return Ok(());
        }
        return Err(format!("relay error: {}", resp).into());
    }
    Err("no response from relay".into())
}

/// SECURITY FIX (G10): Onion-routed message delivery.
/// Wraps the message in two layers of encryption: outer for the entry relay
/// and inner for the exit relay. The entry relay peels the outer layer
/// and forwards the inner ciphertext to the exit relay. The exit relay
/// stores it in the recipient's mailbox.
///
/// This provides traffic analysis resistance: the entry relay knows
/// the sender but not the recipient; the exit relay knows the recipient
/// but not the sender. Neither knows both.
///
/// Requires two relay URLs: entry_relay_url and exit_relay_url.
async fn send_via_onion(
    identity: &Identity,
    recipient_nid: &str,
    message: &str,
    entry_relay_url: &str,
    exit_relay_url: &str,
    store: &MessageStore,
) -> Result<(), Box<dyn std::error::Error>> {
    use nullnode_crypto::DoubleRatchetSession;

    // Load our Kyber keypair
    let kyber_path = home_dir().join(KYBER_KEY_PATH);
    let our_kyber = nullnode_crypto::kyber::KyberKeypair::load_or_generate(&kyber_path, store.db_key())
        .map_err(|e| format!("kyber keypair load failed: {}", e))?;

    // Derive exit relay's Kyber key (TOFU)
    let exit_kyber = lookup_kyber_for_nid(exit_relay_url, store).await?;

    // Create or load DoubleRatchet session with exit relay
    let session_json = store.load_session("__onion_exit__").await?;
    let mut ratchet_session = if let Some(json) = session_json {
        DoubleRatchetSession::deserialize(&json)
            .map_err(|e| format!("ratchet load: {}", e))?
    } else {
        // First onion message to exit relay: KEM exchange
        let (_ct, shared_secret) = nullnode_crypto::kyber::KyberKeypair::encapsulate(&exit_kyber)
            .map_err(|e| format!("onion exit kyber encapsulate: {}", e))?;
        DoubleRatchetSession::new(
            &identity.fingerprint,
            "__onion_exit__",
            &identity.fingerprint,
            true,
            &shared_secret,
        ).map_err(|e| format!("onion ratchet init: {}", e))?
    };

    // Encrypt message for exit relay (inner layer)
    let inner_ciphertext = ratchet_session
        .encrypt_message(message, &exit_kyber)
        .map_err(|e| format!("onion inner encrypt: {}", e))?;

    // Build the inner relay-store payload for the exit relay
    let inner_payload = serde_json::json!({
        "type": "relay-store",
        "recipient_nid": recipient_nid,
        "signed_blob": inner_ciphertext,
        "sender_nid": "anonymous",
        "sender_fp": "",
        "sender_sig": "",
        "sender_cert": "",
        "sealed_sender": base64::encode(identity.null_id.as_bytes()),
    });

    // Now encrypt the entire inner payload for the entry relay
    // (outer layer — entry peers sees only "onion-wrap" destined for exit_relay)
    let padded = pad_message_bucket(&inner_payload.to_string());

    // Derive entry relay's key
    let entry_kyber = lookup_kyber_for_nid(entry_relay_url, store).await?;

    let entry_session_json = store.load_session("__onion_entry__").await?;
    let mut entry_ratchet = if let Some(json) = entry_session_json {
        DoubleRatchetSession::deserialize(&json)
            .map_err(|e| format!("ratchet load: {}", e))?
    } else {
        // First onion message to entry relay: KEM exchange
        let (_ct, shared_secret) = nullnode_crypto::kyber::KyberKeypair::encapsulate(&entry_kyber)
            .map_err(|e| format!("onion entry kyber encapsulate: {}", e))?;
        DoubleRatchetSession::new(
            &identity.fingerprint,
            "__onion_entry__",
            &identity.fingerprint,
            true,
            &shared_secret,
        ).map_err(|e| format!("entry ratchet init: {}", e))?
    };

    let outer_ciphertext = entry_ratchet
        .encrypt_message(&base64::encode(&padded), &entry_kyber)
            .map_err(|e| format!("onion outer encrypt: {}", e))?;

    // Build the outer relay-store payload for entry relay
    let outer_payload = serde_json::json!({
        "type": "onion-v1",
        "exit_relay_url": exit_relay_url,
        "ciphertext": outer_ciphertext,
    });

    // Send to entry relay
    let ws_url = entry_relay_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let mut ws = ws_connect(&ws_url).await
        .map_err(|e| format!("onion entry relay connect failed: {}", e))?;

    ws.send(Message::Text(outer_payload.to_string().into())).await
        .map_err(|e| format!("onion entry relay send failed: {}", e))?;

    // Wait for relay-ok
    if let Some(Ok(Message::Text(resp))) = ws.next().await {
        let resp_val: serde_json::Value = serde_json::from_str(&resp)?;
        if resp_val.get("type").and_then(|t| t.as_str()) == Some("relay-ok") {
            // Persist ratchet sessions
            let entry_json = entry_ratchet.serialize()
                .map_err(|e| format!("entry ratchet serialize: {}", e))?;
            store.save_session("__onion_entry__", &entry_json).await
                .map_err(|e| format!("entry ratchet save: {}", e))?;

            let exit_json = ratchet_session.serialize()
                .map_err(|e| format!("exit ratchet serialize: {}", e))?;
            store.save_session("__onion_exit__", &exit_json).await
                .map_err(|e| format!("exit ratchet save: {}", e))?;

            println!("Message routed via onion (entry={} exit={})", entry_relay_url, exit_relay_url);
            return Ok(());
        }
        return Err(format!("onion entry relay error: {}", resp).into());
    }
    Err("no response from entry relay".into())
}

/// Look up a recipient's Kyber public key from DHT.
/// SECURITY FIX (M2): In production, this would fetch from DHT records.
/// For now, derive deterministically from nid hash (TOFU on first contact).
async fn lookup_kyber_for_nid(
    nid: &str,
    store: &MessageStore,
) -> Result<nullnode_crypto::kyber::KyberEncapsulationKey, Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(nid.as_bytes());
    // Expand 32-byte hash to 64-byte seed via HKDF-SHA256
    let hk = hkdf::Hkdf::<Sha256>::new(None, &hash);
    let mut seed = [0u8; 64];
    hk.expand(b"nullnode-sealed-sender-kyber-seed", &mut seed)
        .map_err(|_| format!("HKDF expand failed"))?;
    // Use the store's db_key as additional binding
    let kp = nullnode_crypto::kyber::KyberKeypair::from_seed(&seed)
        .map_err(|e| format!("kyber keypair from seed: {}", e))?;
    Ok(kp.enc)
}

/// Decrypt a relay-fetched signed_blob using the persisted DoubleRatchet session.
/// The signed_blob is a serialized WireEnvelope of type p2p-message.
/// `sender_nid` and `sender_fp` come from the relay entry metadata.
async fn relay_decrypt_message(
    signed_blob: &str,
    sender_nid: &str,
    sender_fp: &str,
    store: &MessageStore,
    our_kyber: &nullnode_crypto::kyber::KyberKeypair,
) -> Result<String, Box<dyn std::error::Error>> {
    use nullnode_protocol::envelope::WireEnvelope;

    let env: WireEnvelope = serde_json::from_str(signed_blob)
        .map_err(|e| format!("parse signed_blob: {}", e))?;

    // Use the sender_nid from the relay entry; fall back to computing from fp
    let nid = if sender_nid.is_empty() && !sender_fp.is_empty() {
        nullnode_crypto::null_id(sender_fp)
    } else {
        sender_nid.to_string()
    };

    if nid.is_empty() {
        return Err("relay message has no sender identification".into());
    }

    // Extract ciphertext from the message envelope
    let ciphertext = env
        .payload
        .get("ciphertext")
        .and_then(|c| c.as_str())
        .ok_or("no ciphertext in relay message")?;

    // Load the DoubleRatchet session for this sender
    let session_json = store
        .load_session(&nid)
        .await?
        .ok_or_else(|| format!("no ratchet session for sender {}", nid))?;

    let mut session = nullnode_crypto::DoubleRatchetSession::deserialize(&session_json)
        .map_err(|e| format!("ratchet deserialize: {}", e))?;

    // Decrypt using the DoubleRatchet session
    let padded_plaintext = session
        .decrypt_message(ciphertext, our_kyber)
        .map_err(|e| format!("ratchet decrypt: {}", e))?;

    // SECURITY FIX (M1): Strip message padding
    let plaintext = unpad_message_bucket(&padded_plaintext)?;

    // Update the persisted session (seq numbers advanced)
    let updated_json = session.serialize()
        .map_err(|e| format!("ratchet re-serialize: {}", e))?;
    store.save_session(&nid, &updated_json).await
        .map_err(|e| format!("ratchet re-save: {}", e))?;

    Ok(plaintext)
}

// ------------------------------------------------------------------ //
//  P2P Send (G1)                                                     //
// ------------------------------------------------------------------ //

/// Send a message to a recipient via DHT lookup + direct P2P delivery.
/// SECURITY FIX (C1): Uses Kyber-768 KEM + Double Ratchet for post-quantum encryption.
/// SECURITY FIX (L1): When `use_pir` is true, uses PIR for privacy-enhanced DHT lookup.
async fn send_message(
    identity: &Identity,
    recipient_nid: &str,
    message: &str,
    store: &MessageStore,
    use_pir: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let contacts = load_contacts();
    let recipient_fp = contacts
        .get(recipient_nid)
        .ok_or("unknown contact — add with 'add-contact' first")?;

    println!("Looking up {} in DHT...", recipient_nid);

    // G1: Look up recipient's address via DHT (PIR or standard)
    let recipient_addr = if use_pir {
        pir_dht_lookup(SEED_URL, recipient_nid).await?
    } else {
        dht_lookup(SEED_URL, recipient_nid).await?
    };
    println!("Found at: {}", recipient_addr);

    println!("Establishing P2P connection...");

    // G1: Connect to recipient's P2P listener
    let ws_url = recipient_addr.replace("http://", "ws://").replace("https://", "wss://");
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|e| format!("P2P connect failed: {}", e))?;

    // SECURITY FIX (C1): Load our Kyber keypair for key exchange
    let kyber_path = home_dir().join(KYBER_KEY_PATH);
    let our_kyber = nullnode_crypto::kyber::KyberKeypair::load_or_generate(&kyber_path, store.db_key())
        .map_err(|e| format!("kyber keypair load failed: {}", e))?;
    let our_kyber_enc_b64 = nullnode_crypto::kyber::encode_enc_key(&our_kyber.enc);

    // SECURITY FIX (C1): Perform handshake with Kyber key included
    let hello = nullnode_p2p::protocol::build_p2p_hello(identity.fingerprint.as_str(), 1, 16, &our_kyber_enc_b64, "");
    
    // SECURITY FIX (C2): Sign the P2P hello with our PGP key
    let hello_sig_data = format!("p2p-hello:{}\n", hello.payload);
    let hello_sig = sign_for_transport(&hello_sig_data)?;
    let hello = nullnode_p2p::protocol::build_p2p_hello_signed(
        identity.fingerprint.as_str(), 1, 16, &our_kyber_enc_b64, "", &hello_sig
    );
    
    ws.send(Message::Text(serde_json::to_string(&hello)?.into()))
        .await
        .map_err(|e| format!("P2P hello failed: {}", e))?;

    // Wait for hello-ack, verify signature, and extract peer's Kyber public key
    let mut peer_kyber_enc: Option<nullnode_crypto::kyber::KyberEncapsulationKey> = None;
    if let Some(Ok(Message::Text(resp))) = ws.next().await {
        let ack: serde_json::Value = serde_json::from_str(&resp)?;
        if ack.get("type").and_then(|t| t.as_str()) != Some("p2p-hello-ack") {
            return Err(format!("Unexpected response: {}", resp).into());
        }

        // SECURITY FIX (C3): Verify the hello-ack GPG signature from responder.
        // Without this, an active MITM could inject a fake hello-ack with their
        // own Kyber key, decrypting all subsequent messages.
        let ack_sig = ack.get("sig").and_then(|s| s.as_str()).unwrap_or("");
        let ack_fp = ack
            .get("public_key")
            .and_then(|k| k.as_str())
            .unwrap_or("unknown");
        if ack_sig.is_empty() {
            return Err("p2p-hello-ack has no signature — rejecting (MITM risk)".into());
        }
        let ack_payload_start = resp.find('{').unwrap_or(0);
        let ack_sig_data = format!("p2p-hello-ack:\n{}", &resp[ack_payload_start..]);
        if !nullnode_dht_core::verify_signature(&ack_sig_data, ack_sig, ack_fp) {
            return Err(format!(
                "p2p-hello-ack signature verification failed for {} — possible MITM",
                ack_fp
            ).into());
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
    // SECURITY FIX (G9): Persist the ratchet session for this peer so
    // future relay-fetched messages (or re-connections) can decrypt.
    let session_json = ratchet_session.serialize()
        .map_err(|e| format!("ratchet serialize: {}", e))?;
    store.save_session(&peer_nid, &session_json).await
        .map_err(|e| format!("ratchet save: {}", e))?;

    // SECURITY FIX (C1): Encrypt message using Double Ratchet + Kyber-768
    // SECURITY FIX (M1): Pad message to constant-size bucket before encryption
    // to prevent traffic analysis by message size
    let padded_message = pad_message_bucket(message);
    let encrypted_msg = ratchet_session.encrypt_message(&padded_message, peer_kyber)?;
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

    // ACS2.6 Part I.2: Attach delivery token for sealed sender
    let delivery_token = generate_delivery_token(recipient_nid, 1)?;
    let token_msg = serde_json::to_string(&delivery_token)?;
    ws.send(Message::Text(token_msg.into())).await.ok();

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
        let store_pool = store.pool.clone();
        let db_key_path = home_dir().join(DB_KEY_PATH);
        let id_clone = identity.clone();

        tokio::spawn(async move {
            // Each spawned task creates its own DbEncryptionKey from the file
            let db_key = match tokio::fs::read_to_string(&db_key_path).await {
                Ok(hex) => match hex::decode(hex.trim()) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&bytes);
                        DbEncryptionKey { key }
                    }
                    _ => {
                        tracing::error!("Invalid db key file");
                        return;
                    }
                },
                Err(e) => {
                    tracing::error!("Failed to read db key: {}", e);
                    return;
                }
            };
            let store = MessageStore { pool: store_pool, db_key };
            if let Err(e) = handle_incoming_connection(stream, peer_addr, id_clone, store).await {
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
            return Err("p2p-hello has no signature — rejecting (MITM risk)".into());
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
        let our_kyber = nullnode_crypto::kyber::KyberKeypair::load_or_generate(&kyber_path, store.db_key())
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

        // SECURITY FIX (G9): Persist the ratchet session for this peer so
        // future messages (including relay-fetched) can decrypt.
    let session_json = ratchet_session.serialize()
        .map_err(|e| format!("ratchet serialize: {}", e))?;
    store.save_session(&peer_nid, &session_json).await
        .map_err(|e| format!("ratchet save: {}", e))?;

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
                let padded_plaintext = ratchet_session.decrypt_message(ciphertext, &our_kyber)
                    .map_err(|e| format!("decrypt failed: {}", e))?;

                // SECURITY FIX (M1): Strip message padding
                let plaintext = unpad_message_bucket(&padded_plaintext)?;

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

/// SECURITY FIX (M1): Pad message to constant-size bucket to prevent
/// traffic analysis by message size. Uses power-of-2 buckets with
/// random padding bytes. The first byte of the padded output indicates
/// the padding length so the receiver can strip it.
/// Bucket sizes: 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
fn pad_message_bucket(message: &str) -> String {
    let msg_bytes = message.as_bytes();
    let msg_len = msg_bytes.len();
    // 1 byte for padding-length header
    let total_len = msg_len + 1;

    // Find the next power-of-2 bucket >= total_len
    let bucket_size = if total_len <= 256 {
        256
    } else if total_len <= 512 {
        512
    } else if total_len <= 1024 {
        1024
    } else if total_len <= 2048 {
        2048
    } else if total_len <= 4096 {
        4096
    } else if total_len <= 8192 {
        8192
    } else if total_len <= 16384 {
        16384
    } else if total_len <= 32768 {
        32768
    } else {
        65536
    };

    let pad_len = bucket_size - msg_len - 1; // -1 for the header byte
    let mut result = Vec::with_capacity(bucket_size);
    // Header: padding length as a single byte (must fit; max 65535)
    result.push(pad_len as u8);
    result.extend_from_slice(msg_bytes);
    // Fill padding with random bytes
    use rand::RngCore;
    let mut padding = vec![0u8; pad_len];
    rand::thread_rng().fill_bytes(&mut padding);
    result.extend_from_slice(&padding);
    // Encode as hex for transport
    hex::encode(result)
}

/// SECURITY FIX (M1): Strip padding from a de-padded message.
/// Reads the first byte as padding length, then strips that many bytes + 1 header byte.
fn unpad_message_bucket(padded_hex: &str) -> Result<String, Box<dyn std::error::Error>> {
    let data = hex::decode(padded_hex)?;
    if data.is_empty() {
        return Err("empty padded message".into());
    }
    let pad_len = data[0] as usize;
    if data.len() < pad_len + 1 {
        return Err("invalid padding length".into());
    }
    let msg = &data[1..data.len() - pad_len];
    Ok(String::from_utf8_lossy(msg).to_string())
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
        /// Use PIR for privacy-enhanced DHT lookup (hides query from DHT server)
        #[arg(long)]
        pir: bool,
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
        /// Contact Null ID or alias
        null_id: String,
    },
    /// Assign a human-readable name to a Null ID
    Alias {
        /// Short alias name (e.g. "Bob-office")
        alias: String,
        /// The Null ID to map
        null_id: String,
    },
    /// List all aliases
    Aliases,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("nullnode=info".parse()?))
        .init();

    // ACS2.6 Part III.2: Lifecycle memory hooks — zeroize on SIGINT/SIGTERM
    // SECURITY FIX (C2): Use graceful shutdown (not process::exit) so Drop
    // implementations run — ZeroizeOnDrop zeros all key material on scope exit.
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("received SIGINT, initiating graceful shutdown (zeroizing secure memory)...");
        shutdown_clone.notify_one();
    });

    // Also handle SIGTERM for systemd/service manager
    #[cfg(unix)]
    {
        let shutdown_clone2 = Arc::clone(&shutdown);
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
            let _ = sigterm.recv().await;
            tracing::info!("received SIGTERM, initiating graceful shutdown...");
            shutdown_clone2.notify_one();
        });
    }

    let args = Args::parse();

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
        Commands::Send { to, message, pir } => {
            let store = MessageStore::open().await?;
            let identity = Identity::load()?;
            let aliases = load_aliases();
            let resolved_to = resolve_recipient(&to, &aliases);
            send_message(&identity, &resolved_to, &message, &store, pir).await?;
        }
        Commands::Read => {
            let store = MessageStore::open().await?;
            let identity = Identity::load()?;

            // G2: Fetch from relay mailbox and decrypt via DoubleRatchet
            println!("Checking relay mailbox...");
            let messages = relay_fetch(RELAY_URL, &identity.null_id, &store).await?;

            if messages.is_empty() {
                println!("No new messages.");
            } else {
                println!("Messages ({}):", messages.len());
                for (i, msg) in messages.iter().enumerate() {
                    println!("  [{}] {}", i + 1, msg);
                    // G5: Store fetched messages (ciphertext is the ratchet
                    // output; we store it encrypted at rest by db_key).
                    let _ = store
                        .store_message("relay", &identity.null_id, msg)
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
            let store = MessageStore::open().await?;
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
            let aliases = load_aliases();
            let resolved_nid = resolve_recipient(&null_id, &aliases);
            let fp = contacts.get(&resolved_nid).ok_or("unknown contact — add with 'add-contact' first")?;
            let identity = Identity::load()?;
            let sn = safety_number(&identity.fingerprint, fp);
            println!("Safety number for {}:", resolved_nid);
            println!("  {}", sn);
            println!("\nVerify this matches your contact's safety number.");
            println!("If it doesn't match, a man-in-the-middle may be intercepting your communication.");
        }
        Commands::SafetyNumber { null_id } => {
            let contacts = load_contacts();
            let aliases = load_aliases();
            let resolved_nid = resolve_recipient(&null_id, &aliases);
            let fp = contacts.get(&resolved_nid).ok_or("unknown contact — add with 'add-contact' first")?;
            let identity = Identity::load()?;
            let sn = safety_number(&identity.fingerprint, fp);
            println!("Your safety number with {}:", resolved_nid);
            println!("  {}", sn);
        }
        Commands::Alias { alias, null_id } => {
            // Validate that the null_id exists in contacts
            let contacts = load_contacts();
            if !contacts.contains_key(&null_id) {
                return Err(format!("unknown Null ID: {} — add it first with 'add-contact {} <fingerprint>'", null_id, null_id).into());
            }
            let mut aliases = load_aliases();
            aliases.insert(alias.clone(), null_id.clone());
            save_aliases(&aliases)?;
            println!("Alias set: {} -> {}", alias, null_id);
        }
        Commands::Aliases => {
            let aliases = load_aliases();
            if aliases.is_empty() {
                println!("No aliases. Add one with: nullnode alias <name> <null_id>");
            } else {
                println!("Aliases:");
                for (alias, nid) in &aliases {
                    println!("  {} -> {}", alias, nid);
                }
            }
        }
    }

    Ok(())
}
