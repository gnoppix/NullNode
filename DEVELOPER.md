# NullNode developer guide

This document describes the internal architecture, module contracts, ACS2.6 compliance status, and extension points for the NullNode messenger.

---

## Project layout

```
messenger/
├── rust/                           # Rust workspace (full implementation)
│   ├── Cargo.toml                  # Workspace root (8 crates)
│   ├── Makefile                    # Build system
│   ├── protocol/                   # Wire protocol, PoW, envelope types
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs              # Module root
│   │       ├── constants.rs        # DHT/relay/p2p constants
│   │       ├── envelope.rs         # WireEnvelope, DHT message types, tests
│   │       ├── pow.rs              # Argon2id/SHA-256 PoW solve/check, tests
│   │       └── braid.rs            # SPQR braid protocol (chunked key exchange)
│   ├── crypto/                     # ML-KEM-1024 KEM, DoubleRatchetSession, memory hardening
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs              # Module root
│   │       ├── kyber.rs            # ML-KEM-1024 keypair, MlKemVariant enum
│   │       ├── secure_mem.rs       # Guard pages, mlock, secure_zero
│   │       ├── delivery_tokens.rs  # Sealed sender token derivation
│   │       ├── cbnp.rs             # Covert Baseline Noise Protocol
│   │       └── pir.rs              # PIR contact discovery
│   ├── crypto-utils/               # Ed25519 operations, secure deletion
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs
│   ├── dht-core/                   # DHT storage layer (SQLite, K-bucket, TOFU)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── sqlite_store.rs
│   │       ├── types.rs
│   │       ├── crypto_helpers.rs
│   │       ├── pin_cache.rs
│   │       ├── bootstrap_verify.rs
│   │       ├── ratelimit.rs
│   │       ├── bot_log.rs
│   │       ├── dht_node.rs
│   │       └── util.rs
│   ├── p2p/                        # P2P client node library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── handshake.rs
│   │       ├── nat.rs
│   │       ├── peer.rs
│   │       ├── protocol.rs
│   │       ├── transport.rs
│   │       ├── tor.rs
│   │       └── util.rs
│   ├── client/                     # CLI client binary
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   ├── relay/                      # Relay server binary
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   ├── bootstrap/                  # Bootstrap DHT server binary
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   └── doc/                        # Generated man pages
├── LICENSE.md
├── CHANGELOG.md
├── DEVELOPER.md                    # This file
├── FAQ.md
├── WORKLIST.md
└── README.md
```

---

## Module contracts

### `nullnode-protocol` — wire format and proof-of-work

The protocol is JSON over WebSocket. Every message is a `WireEnvelope`:

```rust
pub struct WireEnvelope {
    pub msg_type: MessageType,
    pub payload: Value,
    pub msg_id: String,     // hex string, 16 chars
    pub ts: f64,            // unix timestamp
    pub sig: String,        // base64-encoded signature
}
```

**Message types:**

| Type | Direction | Purpose |
|---|---|---|
| **DHT store-and-forward** | | |
| `dht-put` | node -> DHT | Store encrypted blob with PoW |
| `dht-get` | node -> DHT | Retrieve blob by key |
| `dht-found` | DHT -> node | Blob found response |
| `dht-error` | DHT -> node | Operation failed |
| `dht-addr-record` | node -> DHT | Signed address record |
| **Direct P2P session** | | |
| `p2p-hello` | peer -> peer | Handshake: public key + PoW |
| `p2p-hello-ack` | peer -> peer | Handshake accepted |
| `p2p-message` | peer -> peer | Encrypted message with seq + hash |
| `p2p-ack` | peer -> peer | Delivery confirmation |
| `p2p-ping` / `p2p-pong` | peer -> peer | Keep-alive |
| **Braid protocol** | | |
| `p2p-braid-chunk` | peer -> peer | Chunked key exchange fragment |
| `p2p-braid-complete` | peer -> peer | All chunks received |
| **NAT traversal** | | |
| `nat-punch` / `nat-punch-ack` | peer -> peer | Hole-punching coordination |
| **Federated relays** | | |
| `relay-forward` | relay -> relay | Cross-relay message delivery |
| `relay-purge` | client -> relay | Squelch (delete all messages for recipient after delivery) |
| `route-advertise` | relay -> relay | Share local route table |
| `who-has` / `route-found` | relay -> relay | Route lookup query/response |
| `peer-auth` / `peer-auth-reply` | relay -> relay | Peer authentication |
| **E2E delivery confirmation** | | |
| `p2p-receipt` | peer -> peer | Cryptographic delivery confirmation (signed by recipient after decrypt) |
| **Legacy relay (fallback)** | | |
| `register` / `registered` | client -> relay | Registration |
| `send` / `recv` | client <-> relay | Message send/receive |
| `ack` / `error` | relay -> client | Delivery/error |

**Proof-of-work:**
```rust
// Constants in protocol/src/constants.rs
pub const DHT_POW_DIFFICULTY: u8 = 16;  // 16 leading zero bits
pub const P2P_POW_DIFFICULTY: u8 = 12;  // 12 leading zero bits

// Functions in protocol/src/pow.rs
pow_check(data, nonce, difficulty) -> Result<bool, PowError>
pow_solve(data, difficulty) -> Result<Option<u64>, PowError>
sha256_hex(data) -> String
```

**SECURITY NOTE (H1):** SHA-256 PoW fallback has been removed. Argon2id is mandatory. If memory allocation fails, the operation fails hard.

**Adding a new message type:**
1. Add variant to `MessageType` in `protocol/src/envelope.rs`
2. Add constructor if needed
3. Handle in the appropriate handler (`relay/src/main.rs`, `dht-core/src/dht_node.rs`, `p2p/src/peer.rs`)

---

### `nullnode-crypto` — ML-KEM-1024 KEM, forward secrecy, and key persistence

**ALL user messages use ML-KEM-1024 KEM (NIST Level 5) with optional ML-KEM-768. There is NO classical fallback.**

```rust
// Encrypt plaintext for a recipient
encrypt(plaintext: &str, recipient_kyber_enc: &KyberEncapsulationKey) -> Result<String, CryptoError>

// Decrypt ciphertext using our decapsulation key
decrypt(ciphertext_hex: &str, our_kyber_dec: &KyberDecapsulationKey) -> Result<String, CryptoError>
```

**KEM-then-AEAD construction:**
1. Generate fresh ephemeral ML-KEM keypair per message
2. Encapsulate shared secret with recipient's static public key
3. Combine shared secret with ratchet chain key via SHA-256
4. Derive AES-256-GCM key via HKDF-SHA256
5. Wire format: `ephemeral_pk (1568B) || kyber_ct (1568B) || nonce (12B) || aes_ct`

**DoubleRatchetSession (forward secrecy + persistence):**
```rust
DoubleRatchetSession::new(peer_fp, peer_nid, our_fp, is_initiator) -> Result<Self, CryptoError>
session.encrypt_message(plaintext: &str, peer_kyber_enc: &KyberEncapsulationKey) -> Result<String, CryptoError>
session.decrypt_message(message: &str, our_kyber_keypair: &KyberKeypair) -> Result<String, CryptoError>
session.serialize() -> Result<String, CryptoError>
DoubleRatchetSession::deserialize(json: &str) -> Result<Self, CryptoError>
session.save(path: &Path) -> Result<(), CryptoError>
DoubleRatchetSession::load(path: &Path) -> Result<Self, CryptoError>
```

**Session persistence in client:**
- `MessageStore::open()` creates a `ratchet_sessions` table (peer_nid TEXT PRIMARY KEY, session_data BLOB, updated_at REAL)
- Sessions are persisted after both `send_message` (sender side) and `handle_incoming_connection` (receiver side)
- `relay_parses_message()` decrypts offline relay messages by loading the persisted session via sender NID
- After decryption, the updated session state is re-saved (ratchet sequence numbers advance)

**Design rules:**
1. `encrypt()` and `decrypt()` return `CryptoResult` — callers must handle errors
2. Ratchet state can be persisted via `save()`/`load()` for session survival across restarts
3. Key derivation uses HKDF-SHA256
4. All random values use `rand::thread_rng()` (cryptographic)
5. **NO classical fallback** — ML-KEM KEM is mandatory for all user messages
6. Each message uses a unique ephemeral keypair (forward secrecy)
7. Kyber keys are persisted with 0o600 permissions
8. Persistence files use JSON format for auditability

---

### `nullnode-crypto-utils` — OpenPGP and secure utilities

In-process Sequoia OpenPGP operations (no shell-out to gpg binary).

```rust
export_pubkey() -> CryptoUtilsResult<String>
import_pubkey(armored: &str) -> CryptoUtilsResult<String>
get_fingerprint_from_armored(armored: &str) -> CryptoUtilsResult<String>
get_own_fingerprint() -> CryptoUtilsResult<String>
validate_fingerprint(fp: &str) -> bool
null_id_from_fingerprint(fp: &str) -> String
secure_delete(path: &str) -> CryptoUtilsResult<()>
```

**Design rules:**
1. All OpenPGP operations use Sequoia (in-process, no shell-out)
2. Fingerprints must be validated (32 or 40 hex chars) before use
3. Certs are cached in dht-core and relay for TOFU-based verification
4. `secure_delete` is best-effort (CoW filesystems may not fully erase)

---

### `nullnode-dht-core` — Kademlia DHT node

```rust
NodeConfig {
    null_id: String,
    fingerprint: String,
    host: String,
    port: u16,
    db_path: Option<String>,
}

DhtNodeRuntime::new(config).await -> Self
runtime.start().await -> Result<()>

DhtStore::new(path: &str) -> Self
store.put(key, value, salt, seq, publisher_fp, ttl) -> Result<()>
store.get(key) -> Option<KvRecord>

pin_get(null_id: &str) -> Option<String>
pin_update(null_id: &str, address: &str) -> Result<()>
pin_verify_address(null_id: &str, address: &str) -> bool

verify_bootstrap_cert(seed_url: &str, pin_cache: &Path) -> Result<CertInfo>
bootstrap_pin_check(seed_url: &str, cert_fp: &str, not_before: &str, not_after: &str) -> bool
domain_matches(cert_domain: &str, pattern: &str) -> bool
cert_has_trusted_domain(cert_info: &CertInfo) -> bool
cert_issuer_is_trusted(cert_info: &CertInfo) -> bool
constant_time_compare(a: &str, b: &str) -> bool
```

**DHT constants:**

| Constant | Value | Purpose |
|---|---|---|
| `DHT_PORT` | 6881 | Default DHT port |
| `K_BUCKET_SIZE` | 8 | Entries per routing bucket |
| `STORE_TTL` | 86400 s | Message TTL (24h) |
| `ADDR_TTL` | 7200 s | Address record TTL (2h) |
| `MAX_VALUE_SIZE` | 4096 | Max encrypted blob size |
| `MAX_STORE_PER_KEY` | 100 | Max messages per mailbox |
| `POW_MAX_AGE` | 300 s | PoW nonce validity window |

**Address ownership verification:**
- Publisher signs: `null_id|address|ttl`
- Signature verified against publisher's OpenPGP cert (in-process via Sequoia)
- `null_id` must equal `compute_null_id(publisher_fp)` (proves key ownership)
- Stored in DHT with salt prefix `"addr:"` to distinguish from mailbox data

**TOFU pinning:**
- First address received for a null_id is trusted and pinned to disk
- Subsequent addresses for the same null_id must match the pin
- Pin mismatch logs a warning and rejects the address (possible MITM)
- Pin cache stored at `~/.nullnode/pin_cache.json`

**Security:**
- Every `dht-put` requires valid PoW (difficulty 16)
- Publisher must sign `key|value|salt|seq|nonce`
- Key must equal publisher's null_id (prevents unauthorized storage)
- Anti-replay via nonce tracking
- Rate limiting: connection (50/60s), query (200/60s), max value size (1KB)
- SECURITY FIX (G7): Fingerprint sanitized before filesystem use (path traversal prevention)
- SECURITY FIX (G9): Rate limiter capped at 100k buckets (memory exhaustion prevention)
- SECURITY FIX (G8): Session serialization includes pending ciphertext; stored with 0o600
- SECURITY FIX (G10): PoW parameters validated (nonce range, difficulty) before hashing

---

### `nullnode-p2p` — P2P client node

```rust
P2pConfig {
    nid: String,
    fingerprint: String,
    bootstrap: Vec<String>,
    transport: TransportConfig,
}

P2pNode::new(config) -> Self
node.start().await -> Result<()>
node.send_message(peer_nid, peer_fp, text) -> Result<bool>
```

**Transport layer:**

```rust
TransportConfig {
    use_tor: bool,
    tor_socks_host: String,
    tor_socks_port: u16,
    tor_control_port: u16,
    tor_control_password: String,
    onion_port: u16,
    onion_address: String,
}

TorHiddenServiceManager::new(config) -> Self
manager.start() -> String       // returns .onion address (or empty)
manager.stop()
manager.is_available() -> bool
manager.get_onion_address() -> String

build_onion_uri(onion: &str, port: u16) -> String
is_onion_address(addr: &str) -> bool
normalize_peer_address(addr: &str, config) -> String
transport_from_env() -> TransportConfig
```

**NAT traversal:**

```rust
StunProtocol::new(host: &str, port: u16) -> Self
protocol.get_public_endpoint() -> Result<(String, u16)>
protocol.parse_response(data: &[(u8, SocketAddr)]) -> Option<(String, u16)>
hole_punch(local_port: u16, peer_ip: &str, peer_port: u16) -> Option<UdpSocket>
connect_through_tor(socks_addr: &SocketAddr, target_host: &str, target_port: u16)
    -> MaybeTlsStream<TcpStream>
```

**Design rules:**
1. When `use_tor=True`, ALL outgoing connections go through Tor SOCKS proxy
2. When Tor is enabled, listener binds on `127.0.0.1` (Tor connects via hidden service)
3. The `.onion` address is self-authenticating (derived from Ed25519 key)
4. Pin cache at `~/.nullnode/bootstrap_pin_cache.json`
5. STUN is optional; Tor removes the need for public endpoint discovery

---

### `nullnode-relay` — WebSocket relay server

```rust
// CLI: --host, --port, --peer, --secret
RelayState::new() -> Self
state.handle_connection(ws).await
```

**Configurable constants:**

| Constant | Default | Purpose |
|---|---|---|
| `MAX_QUEUED` | 100 | Max offline messages per recipient |
| `QUEUE_TTL` | 300 s | Drop queued messages older than this |
| `MAX_SESSIONS_PER_NID` | 10 | Max concurrent sessions per Null ID |
| `MAX_TOTAL_QUEUED` | 10_000 | Global queue cap |
| `MAX_MSG_SIZE` | 1 MB | Max envelope size |
| `CONN_RATE_MAX` | 50 | Max connections per 60s per IP |
| `MSG_RATE_MAX` | 120 | Max messages per 60s per IP |
| `CONN_IDLE_TIMEOUT` | 300 s | Idle connection timeout |
| `MAX_PEER_RELAYS` | 20 | Max federated peer relays |
| `ROUTE_TTL` | 1800 s | Remote route expiry |
| `GOSSIP_INTERVAL` | 60 s | Route advertisement interval |

**Message flow (relay with federation):**

```
register:
  1. WebSocket connection accepted (ws:// or wss://)
  2. Per-IP rate limiting check
  3. Heartbeat loop starts (30s ping/pong)

relay-store (client -> relay):
  1. Verify envelope timestamp freshness (+/- 300s)
  2. Verify sender signature (Sequoia in-process)
  3. Check timestamp freshness (replay protection)
  4. Check and record nonce (replay protection)
  5. Store in recipient's mailbox (per-sender cap: 10, global: 1000)
  6. If recipient in remote_routes -> relay-forward to peer relay

relay-fetch (client -> relay):
  1. Verify signature proving requester owns identity (Sequoia in-process)
  2. Verify null_id matches fingerprint derivation
  3. Check nonce replay
  4. Verify HMAC if shared secret configured
  5. Return mailbox entries (TTL 7 days)

route-advertise (relay -> relay):
  1. Update remote_routes with advertised Null IDs
  2. Update peer last_seen timestamp
  3. Respond with route-advertise-ack containing our local Null IDs

relay-forward (relay -> relay):
  1. Verify inner signature
  2. Check hop_count < MAX_RELAY_HOPS (5)
  3. Loop detection: check via chain doesn't contain us
  4. Check nonce replay
  5. Store in local mailbox
  6. Send relay-forward-ack

gossip_task (background, every 60s):
  1. Collect local Null IDs from mailboxes
  2. Build route-advertise envelope
  3. Send to all connected peers
  4. Cleanup expired routes (> 30min) and stale peers (> 5min)
```

---

### `nullnode-client` — CLI entry point

```rust
cmd_init(config)          // Generate identity
cmd_id(config)            // Show Null ID + fingerprint
cmd_export()              // Print armored public key
cmd_import(armored)       // Import from file or stdin
cmd_contacts()            // List registered contacts
cmd_add_contact(nid, fp)  // Add a contact with fingerprint
cmd_alias(name, nid)      // Assign human-readable alias to a Null ID
cmd_aliases()             // List all aliases
cmd_send(nid_or_alias, msg) // Send message to peer (DHT lookup + P2P delivery)
cmd_read()                // Read messages from relay mailbox
cmd_listen(config)        // Start P2P listener for incoming connections
cmd_chat(nid_or_alias)    // Interactive P2P chat
cmd_verify(nid_or_alias)  // Verify contact safety number (G6)
cmd_safety_number(nid_or_alias) // Show safety number for a contact (G6)
cmd_status()              // Show DHT status
```

**Alias resolution:**

The client uses `resolve_recipient(input, aliases)` to map user-provided recipients (in `send`, `chat`, `verify`, `safety-number`) to Null IDs. If the input matches a known alias, it returns the mapped Null ID; otherwise it passes the input through unchanged. This means raw Null IDs always work.

**Configuration paths:**

| Path | Purpose |
|---|---|
|| `~/.nullnode/identity.json` | Own Null ID + fingerprint |
|| `~/.nullnode/contacts.json` | NID -> fingerprint mapping |
|| `~/.nullnode/aliases.json` | Alias -> NID mapping (human-readable names) |
|| `~/.nullnode/pin_cache.json` | DHT address TOFU pins |
| `~/.nullnode/bootstrap_pin_cache.json` | Bootstrap TLS cert TOFU pins |
| `~/.nullnode/dht_store.db` | SQLite DHT storage |
| `~/.nullnode/messages.db` | SQLite message store (AES-256-GCM encrypted) |
| `~/.nullnode/db_key.json` | Database encryption key (0o600) |
| `~/.nullnode/delivery_secrets.json` | Per-contact delivery master secrets (0o600) |
| `~/.nullnode/kyber_keys.json` | Persisted ML-KEM keypair (0o600) |
| `~/.nullnode/ratchet_sessions/` | Persisted ratchet sessions (0o600) |
| `~/.nullnode/known_peers.json` | Relay TOFU peer fingerprints |

---

### `nullnode-bootstrap` — Bootstrap DHT server

```rust
// CLI: --host, --port, --id, --db, --advertised-url
// Starts a DHT WebSocket server on the specified port
// Stores data in SQLite at the specified path
// --advertised-url sets the public URL (wss://...) when behind nginx
```

#### Nginx TLS Proxy Deployment

For production, run the bootstrap behind nginx on :443:

```bash
# Bootstrap binds to localhost only — nginx terminates TLS
./target/release/nullnode-bootstrap \
    --host 127.0.0.1 --port 9001 \
    --advertised-url wss://bootstrap.example.com/ws
```

The `--advertised-url` flag sets `NodeConfig.advertised_url`, which the DHT node
uses as its public address in DHT records instead of `host:port`. Clients
discovering this node via DHT will connect through the nginx proxy using
`wss://` (TLS 1.3).

See `docs/nginx-proxy.md` for the full nginx configuration including WebSocket
upgrade headers, fallback static page, and rate limiting.

---

## ACS2.6 Compliance Status

NullNode implements the Architectural & Cryptographic Specification v2.6. This section tracks compliance.

### Part I: Core P2P Messaging & Metadata Protection

| ACS2.6 Requirement | Status | Notes |
|-----------------|--------|-------|
| **ML-KEM-1024** (instead of Kyber-768) | ✅ Complete | `ml-kem 0.3.2` with MlKem1024 (NIST Level 5); dual-variant support (768/1024) via `MlKemVariant` config |
| **ML-KEM Braid Protocol (SPQR)** | ✅ Complete | `protocol/src/braid.rs`: Chunked key exchange with BraidChunk + BraidHandshake structs |
| **Sealed Sender with Delivery Tokens** | ✅ Complete | `delivery_tokens` module: HMAC-SHA256 HKDF-like derivation, 28-byte constant-size tokens, replay protection |
| **PQ-Sender Keys (Group Messaging)** | ❌ Not implemented | No group messaging support or ML-DSA-87 signing |
| **PIR Contact Discovery** | ✅ Complete | `pir` module: Blind registries with cuckoo hashing, XOR-masked bins. 4KB bins, 18 entries/bin. Local cache in client |

### Part II: Mobile, Bandwidth & Push Architecture

| ACS2.6 Requirement | Status | Notes |
|-----------------|--------|-------|
| **Adaptive Traffic Budgeting Engine** | ❌ Not implemented | No network state detection or Poisson streams |
| **PQ-PPN (Push Notifications)** | ❌ Not implemented | No push proxy or zero-knowledge triggers |
| **Edge-Core Relay Mode** | ✅ Complete | `--allow-relay` flag: default false (edge), must opt-in for core federation transit |

### Part II-B: Delivery & Squelch

| ACS2.6 Requirement | Status | Notes |
|-----------------|--------|-------|
| **E2E Delivery Receipt** | ✅ Complete | `p2p-receipt`: signed by recipient after decrypt, proves delivery without revealing content |
| **Relay Purge/Squelch** | ✅ Complete | `relay-purge`: authenticated deletion of all messages after successful delivery |

### Part III: Local Data-at-Rest Protection

| ACS2.6 Requirement | Status | Notes |
|-----------------|--------|-------|
| **Hardware-Bound Key Hierarchy** | ❌ Not implemented | No HSM integration or Argon2id user-derived keys |
| **Hardened SQLCipher (Page-Level Randomization)** | ⚠️ Partial | SQLite encrypted but no 4096B page randomization |
| **Memory Protection (mlock, secure_zero, guard pages)** | ✅ Complete | `crypto/src/secure_mem.rs`: `GuardedKeyMaterial` with mmap guard pages (PROT_NONE), `secure_zero_memory`, `lock_memory` |
| **Biometric Access Lifecycles** | ❌ Not implemented | No app lifecycle hooks for key scrubbing |

### Part IV: Network Resilience

| ACS2.6 Requirement | Status | Notes |
|-----------------|--------|-------|
| **DPI Evasion / Pluggable Transports** | ✅ Partial | TLS/WebSocket optional (`wss://`). Tor SOCKS5 support exists |
| **Certificate-Based Core Node Admission** | ✅ Complete | TOFU peer certificate pinning: relay maintains `.known_peers.json`, auto-accepts first-seen, rejects unknown |

### Part V: Real-World Implementation Defenses

| ACS2.6 Requirement | Status | Notes |
|-----------------|--------|-------|
| **Coordinated Baseline Noise Protocol (CBNP)** | ✅ Complete | `cbnp` module: Poisson-timed cover traffic (exponential inter-arrival), 3200-byte dummy packets, burst mode, `is_cover_traffic()` detection. Wired into relay background task |
| **Bloom-Filtered Delta Syncing** | ❌ Not implemented | No compressed mailbox polling |
| **Guard Pages / VirtualLock** | ✅ Complete | `GuardedKeyMaterial`: Rust key material allocated between PROT_NONE mmap pages; buffer overflows trigger immediate SIGSEGV |

### Part VI: Sovereign Infrastructure Hardening

| ACS2.6 Requirement | Status | Notes |
|-----------------|--------|-------|
| **Decentralized Hardware Attestation** | ❌ Not implemented | No REPORT_DATA binding, VCEK verification, or LAUNCH_MEASUREMENT checks |
| **Geopolitical Traffic Partitioning** | ❌ Not implemented | No jurisdiction-aware routing or WireGuard mesh tunnels |

---

## Currently Implemented Security Features

| Feature | ACS2.6 Mapped Requirement |
|---------|---------------------------|
| ML-KEM-1024 KEM for key exchange | Part I.1 (variant: 768 or 1024) |
|| Double Ratchet with HKDF chain key + session persistence | Part I.1 (complete) |
| GPG secret key encryption at rest (age passphrase) | Part III.2 (new) |
| Memory zeroization (ZeroizeOnDrop on all secret structs) | Part III.2 (new) |
| P2P mutual authentication (GPG-signed hello + hello-ack) | Part III.2 (new) |
| Relay federation peer authentication enforcement | Part III.2 (new) |
| Relay mailbox persistence (SQLite, 0o600 perms, ciphertext blobs) | Part III.2 (new) |
| Argon2id PoW (DHT: 16MB/3iter, P2P: 1MB/2iter) | Part I.5 anti-spam |
| HMAC federation authentication | Part I.4 (partial) |
| TLS/WebSocket transport (optional) | Part IV.1 DPI evasion |
| Tor SOCKS5 transport support | Part IV.1 DPI evasion |
| Sequoia in-process OpenPGP | Part III (signing/verification) |
| Rate limiting (connection + GET) | Part I.5 anti-abuse |
| Bot/scanner detection | Part V.4 security framework |
| CBNP (Coordinated Baseline Noise Protocol) | Part V.1 cover traffic |
| Delivery tokens (sealed sender) | Part I.3 metadata protection |
| PIR blind contact discovery | Part I.3 private discovery |
| TOFU certificate pinning | Part IV.2 core node admission |
| Guard pages + mlock | Part III.3 memory protection |
| AES-256-GCM database encryption at rest | Part III.2 data protection |
| SIGINT graceful shutdown | Part III.2 lifecycle hooks |
| E2E delivery receipt (`p2p-receipt`) | Part II-B delivery confirmation |
| Relay purge/squelch (`relay-purge`) | Part II-B squelch after delivery |
| Edge-core relay mode (`--allow-relay`) | Part II mobile/battery protection |

---

## Future Implementation Priority

1. ~~**ML-KEM-1024 upgrade**~~ ✅ Done
2. ~~**Memory protection**~~ ✅ Done
3. ~~**Delivery tokens**~~ ✅ Done
4. ~~**CBNP**~~ ✅ Done
5. ~~**PIR contact discovery**~~ ✅ Done
6. ~~**TOFU certificate pinning**~~ ✅ Done
7. ~~**Database encryption**~~ ✅ Done
8. ~~**Lifecycle hooks**~~ ✅ Done
9. ~~**Braid Protocol**~~ ✅ Done
9b. ~~**DoubleRatchet session persistence**~~ ✅ Done — SQLite `ratchet_sessions` table wired into send/receive paths
9c. ~~**GPG secret key encryption**~~ ✅ Done — age passphrase protects own_cert.age on disk
9d. ~~**Memory zeroization**~~ ✅ Done — ZeroizeOnDrop on DoubleRatchetSession, DbEncryptionKey, VariantKeypair; graceful SIGINT/SIGTERM shutdown
9e. ~~**P2P mutual authentication**~~ ✅ Done — GPG-signed hello + hello-ack, reject unsigned, relay federation auth enforcement
9f. ~~**E2E delivery receipt**~~ ✅ Done — `p2p-receipt` signed after decrypt, with 10s timeout loop in sender
9g. ~~**Relay purge/squelch**~~ ✅ Done — `relay-purge` authenticated deletion, wired into `nullnode read`
9h. ~~**Edge-core relay mode**~~ ✅ Done — `--allow-relay` flag (default: edge), rejects federation transit
10. **Biometric access lifecycle** — Key scrubbing on app background/lock
11. **Hardware-bound keys** — Argon2id user-derived keys, HSM integration

---

## Testing

```bash
# Run all tests
make test

# Run specific package tests
make test-crypto
make test-p2p
make test-dht
make test-protocol

# Fast compilation check
make check

# Clippy linter
make lint
```

**Test coverage:**

| Crate | Tests | Coverage |
|---|---|---|
| `nullnode-protocol` | 14 | PoW solve/check, envelope roundtrip, GPG sign/verify, braid (5) |
| `nullnode-p2p` | 2 | Transport, handshake |
| `nullnode-dht-core` | 17 | DHT node, SQLite, ratelimit, pin_cache, bootstrap_verify |
| `nullnode-crypto` | 38 | encrypt/decrypt, ratchet, key derivation, kyber persistence, secure_mem (4), delivery_tokens (4), cbnp (3), pir (8) |
| `nullnode-crypto-utils` | 4 | export/import, fingerprint validation, secure_delete |
| `nullnode-relay` | 11 | URL parse, HMAC, route table, nonce replay, loop detection |
| **Total** | **86** | |

---

## Building

```bash
# Build all binaries (release)
make all

# Build specific binary
make client
make relay
make bootstrap

# Build debug
make debug

# Install to /usr/local/bin
sudo make install

# Build static binary (requires musl target)
make static

# Generate man page
make man
```

**Output binaries:**

| Binary | Size | Description |
|---|---|---|
| `target/release/nullnode` | ~7 MB | CLI client |
| `target/release/nullnode-relay` | ~5 MB | Relay server |
| `target/release/nullnode-bootstrap` | ~4 MB | Bootstrap DHT server |

---

## Security considerations

1. **No automatic trust** — keys must be explicitly trusted after out-of-band verification
2. **Safety number verification** (G6) — deterministic safety number from both parties' fingerprints enables out-of-band key verification
3. **Constant-time comparison** — used for fingerprint comparison to prevent timing attacks
4. **Secure deletion** — temp files overwritten with random bytes before unlink
5. **TOFU pinning** — first-seen addresses and TLS certs are pinned to disk
6. **Rate limiting** — prevents DoS and spam on DHT and relay
7. **Tor support** — optional IP masking for all network traffic
8. **Bootstrap verification** — TLS cert domain, CA, and TOFU checks prevent rogue servers
9. **PoW anti-spam** — Argon2id memory-hard puzzles make bulk abuse infeasible
10. **Key persistence** — All persisted keys and sessions use 0o600 permissions
11. **Double ratchet** — Forward secrecy with per-message key derivation; sessions persist across restarts in SQLite ratchet_sessions table
11b. **GPG secret key encryption** — `age` passphrase encryption (scrypt recipient, XChaCha20-Poly1305); stored at own_cert.age (0o600); supports empty passphrase for opt-out
11c. **Memory zeroization** — All secret structs use `ZeroizeOnDrop` derive; SIGINT/SIGTERM triggers graceful shutdown (not process::exit) so drop glue zeroes keys
11d. **P2P mutual authentication** — Both initiator and responder verify GPG signatures on hello/hello-ack. Unsigned hellos are rejected (not just warned). Prevents active MITM from injecting fake Kyber keys.
11e. **Relay federation enforcement** — `relay-forward` messages require `peer.authenticated == true` when `shared_secret` is configured. `RelayForward.source_relay_url` enables receiver to look up sender auth state.
11f. **Relay mailbox persistence** — SQLite database (`mailbox.db`, 0o600) stores mailbox entries with ciphertext blobs. Messages survive relay restart. In-memory cache kept for fast reads.
12. **Signed P2P handshake** — All P2P messages are signed to prevent MITM attacks
13. **Signature verification** — Incoming P2P messages verify sender signature before processing
14. **Encrypted message storage** — SQLite database stores only ciphertext; no plaintext ever written to disk
15. **Guard pages** — key material between PROT_NONE mmap pages; buffer overflows trigger SIGSEGV
16. **CBNP cover traffic** — Poisson-timed dummy packets prevent traffic analysis during idle periods
17. **E2E delivery receipts** — `p2p-receipt` signed by recipient proves message was decrypted (not just received)
18. **Relay squelch** — `relay-purge` deletes all mailbox entries after successful delivery+decrypt, preventing stale ciphertext accumulation
19. **Edge-core relay mode** — Mobile nodes default to edge mode (no transit forwarding); `--allow-relay` opts in to core/federation transit
20. **HMAC dual-auth on purge** — When relay has shared_secret, `relay-purge` requires both GPG signature and HMAC

---

## Relay Federation

Multi-relay federation allows messages to route between relay servers:

1. **Peer connections** — `connect_to_peer()` maintains persistent WebSocket connections to peer relays
2. **Route advertisement** — `gossip_task()` periodically advertises known null_ids to connected peers
3. **Cross-relay forwarding** — `forward_to_peer()` sends relay-forward messages to peer relays
4. **Route lookup** — `FederationState::lookup_route()` determines which peer serves a given null_id
5. **HMAC optional auth** — Federation can use shared-secret HMAC for peer authentication

**Known limitation**: Federation currently requires manual peer URL configuration via command-line. Automatic peer discovery will be implemented in a future phase.

---

## Delivery architecture

NullNode uses a two-tier delivery system with cryptographic confirmation at each stage.

### Delivery flow (sender side)

```
send_message()
  ├─ DHT lookup (bootstrap seed) → recipient WebSocket address
  ├─ P2P connect + handshake (Kyber-1024 KEM, GPG-signed)
  ├─ Double Ratchet encrypt + send p2p-message
  ├─ Wait for responses (10s timeout loop):
  │   ├─ p2p-ack → "Message delivered successfully!"
  │   └─ p2p-receipt → "Message READ by peer at HH:MM:SS [E2E confirmed]"
  └─ Store sent message locally (ciphertext only)
```

If P2P fails (timeout, offline peer), the message falls back to relay-store.

### Relay mailbox flow (recipient side)

```
nullnode read (client)
  ├─ relay-fetch: signed request → relay returns encrypted entries
  ├─ relay_decrypt_message(): load DoubleRatchetSession from SQLite, decrypt
  ├─ Display plaintext to user
  └─ relay-purge: signed squelch request → relay deletes ALL messages
                  for this null_id (in-memory + SQLite)
```

### `p2p-receipt` — E2E delivery confirmation

The receipt proves the recipient has decrypted the message (not just received it).

```
Recipient side (handle_incoming_connection):
  1. Decrypt p2p-message via DoubleRatchetSession
  2. Send p2p-ack (transport confirmation)
  3. Send p2p-receipt:
     - Signs: "p2p-receipt:{msg_hash}:{received_at}:{seq}"
     - Uses recipient's own GPG key (sign_for_transport)
     - Sent as a WireEnvelope with msg_type = "p2p-receipt"

Sender side (send_message response loop):
  1. Parse incoming WireEnvelope
  2. If type == "p2p-receipt":
     a. Extract msg_hash, received_at, sig from payload
     b. verify_receipt_signature() → dht_core::verify_signature()
     c. On success: display "Message READ by peer at {time} [E2E confirmed]"
     d. On failure: display warning (possible forged receipt)
```

### `relay-purge` — Squelch after delivery

Prevents stale ciphertext accumulation on the relay after messages have been successfully delivered and decrypted.

```
Client sends:
  {
    "type": "relay-purge",
    "recipient_nid": "<own null_id>",
    "requester_fp": "<own fingerprint>",
    "sender_sig": "<GPG signature over 'relay-purge:{nid}:{ts}:{nonce}'>",
    "timestamp": <unix_ts>,
    "nonce": "<uuid>"
  }

Relay verifies:
  1. Timestamp freshness (±300s)
  2. null_id == compute_null_id(fingerprint) (proves key ownership)
  3. GPG detached signature verification (in-process via Sequoia)
  4. Nonce replay check (prevents re-purging)
  5. DELETE ALL mailbox entries for this null_id
```

### Edge-core relay mode (`--allow-relay`)

```
relay-forward handler:
  if !state.allow_relay:
    → Send relay-forward-ack { accepted: false, error: "edge mode" }
    → Return (do not forward)
  else:
    → Process forwarding to peer relay
```

This allows mobile/battery nodes to run a local relay without becoming transit points in the federation.

### Delivery confirmation levels

| Level | Wire message | What it proves | Verification |
|---|---|---|---|
| Relay stored | `relay-store` response `"ok"` | Message reached relay mailbox | HMAC + signature |
| P2P received | `p2p-ack` | Peer's WebSocket received the message | GPG signature (peer key) |
| P2P read | `p2p-receipt` | Peer decrypted the message content | GPG signature (peer key) + msg_hash |

### Key source locations

| Component | File | Function |
|---|---|---|
| Send message (P2P) | `client/src/main.rs` | `send_message()` |
| Recv message (P2P) | `client/src/main.rs` | `handle_incoming_connection()` |
| Receipt builder | `p2p/src/protocol.rs` | `build_p2p_receipt()` |
| Receipt verifier | `client/src/main.rs` | `verify_receipt_signature()` |
| Relay purge handler | `relay/src/main.rs` | `"relay-purge"` match arm |
| Purge DB + memory | `relay/src/main.rs` | `purge_all_messages()` |
| Client purge sender | `client/src/main.rs` | `relay_purge()` |
| Edge-core enforcement | `relay/src/main.rs` | `if !state.allow_relay` in `relay-forward` |
| Message type constants | `protocol/src/constants.rs` | `MSG_RELAY_PURGE`, `MSG_P2P_RECEIPT` |

## References

1. https://dehornoy.lmno.cnrs.fr/Surveys/Dgw.pdf

---

## License

Business Source License (BSL / BUSL).
You can use the code for free if your company or organisation doesn't have more than 2 people.

---
Copyright (c) 2026 Andreas Mueller — gnoppix.com
