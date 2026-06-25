# NullNode developer guide

This document describes the internal architecture, module contracts, and
extension points for the NullNode messenger.

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
│   │       └── pow.rs              # Argon2id/SHA-256 PoW solve/check, tests
│   ├── crypto/                     # Kyber-768 KEM (ALL messages), DoubleRatchetSession
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs              # encrypt/decrypt (Kyber-768 KEM), ratchet, key derivation
│   │   │   └── kyber.rs            # Kyber-768 keypair type (re-export from ml-kem)
│   ├── crypto-utils/               # Ed25519 operations, secure deletion
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs              # export_pubkey, import_pubkey, secure_delete
│   ├── dht-core/                   # DHT storage layer (SQLite, K-bucket, TOFU)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs              # Module root, error types
│   │       ├── sqlite_store.rs     # DhtStore: SQLite-backed KvRecord storage
│   │       ├── types.rs            # DhtNode, NodeConfig, RoutingEntry
│   │       ├── crypto_helpers.rs   # sign/verify, Null ID derivation, constant_time_compare
│   │       ├── pin_cache.rs        # TOFU pinning cache (JSON file)
│   │       ├── bootstrap_verify.rs # Bootstrap TLS cert verification
│   │       ├── ratelimit.rs        # Async sliding-window rate limiter
│   │       ├── bot_log.rs          # Bot/scanner activity logger
│   │       └── dht_node.rs         # DhtNodeRuntime (async WebSocket server)
│   │       └── util.rs             # Timestamp, UUID, hex helpers
│   ├── p2p/                        # P2P client node library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs              # P2pNode, P2pConfig
│   │       ├── handshake.rs        # p2p-hello/-ack with PoW
│   │       ├── nat.rs              # STUN + hole punching
│   │       ├── peer.rs             # Peer connection management
│   │       ├── protocol.rs         # Message types
│   │       ├── transport.rs        # Direct + SOCKS5/Tor WebSocket
│   │       ├── tor.rs              # Tor hidden service manager
│   │       └── util.rs             # P2P utilities
│   ├── client/                     # CLI client binary
│   │   ├── Cargo.toml
│   │   └── src/main.rs             # init, id, export, import, contacts, send, read, listen, chat, verify, safety-number
│   ├── relay/                      # Relay server binary (store-and-forward)
│   │   ├── Cargo.toml
│   │   └── src/main.rs             # WebSocket relay with rate limiting
│   ├── bootstrap/                  # Bootstrap DHT server binary
│   │   ├── Cargo.toml
│   │   └── src/main.rs             # CLI: --host, --port, --id, --db
│   └── doc/                        # Generated man pages
├── LICENSE.md
├── CHANGELOG.md
├── DEVELOPER.md                    # This file
├── FEATURES.md
├── FAQ.md
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

**Message types (current):**

| Type | Direction | Purpose |
|---|---|---|
| **DHT store-and-forward** | | |
| `dht-put` | node -> DHT | Store encrypted blob with PoW |
| `dht-get` | node -> DHT | Retrieve blob by key |
| `dht-found` | DHT -> node | Blob found response |
| `dht-error` | DHT -> node | Operation failed |
| `dht-addr-record` | node -> DHT | Signed address record (proves key ownership) |
| **Direct P2P session** | | |
| `p2p-hello` | peer -> peer | Handshake: public key + PoW |
| `p2p-hello-ack` | peer -> peer | Handshake accepted |
| `p2p-message` | peer -> peer | Encrypted message with seq + hash |
| `p2p-ack` | peer -> peer | Delivery confirmation |
| `p2p-ping` | peer -> peer | Keep-alive |
| `p2p-pong` | peer -> peer | Keep-alive response |
| **NAT traversal** | | |
| `nat-punch` | peer -> peer | Hole-punching coordination |
| `nat-punch-ack` | peer -> peer | Hole-punching acknowledged |
| **Federated relays** | | |
| `relay-forward` | relay -> relay | Cross-relay message delivery |
| `route-advertise` | relay -> relay | Share local route table |
| `who-has` | relay -> relay | Query for a Null ID's relay |
| `route-found` | relay -> relay | Response to who-has |
| `peer-auth` | relay -> relay | Challenge for peer relay auth |
| `peer-auth-reply` | relay -> relay | Challenge response |
| **Legacy relay (fallback)** | | |
| `register` | client -> relay | Register Null ID |
| `registered` | relay -> client | Registration confirmed |
| `send` | client -> relay | Send message via relay |
| `recv` | relay -> client | Receive message |
| `ack` | relay -> sender | Delivery acknowledgment |
| `error` | relay -> client | Error notification |

**Proof-of-work:**
```rust
// Constants defined in protocol/src/constants.rs
pub const DHT_POW_DIFFICULTY: u8 = 16;  // 16 leading zero bits
pub const P2P_POW_DIFFICULTY: u8 = 12;  // 12 leading zero bits

// Functions in protocol/src/pow.rs
pow_check(data, nonce, difficulty) -> Result<bool, PowError>  // Argon2id-only verification (no SHA-256 fallback)
pow_solve(data, difficulty) -> Result<Option<u64>, PowError>   // Argon2id-only solver
sha256_hex(data) -> String                                  // SHA-256 for fingerprinting (NOT for PoW)
```

**SECURITY NOTE (H1):** SHA-256 PoW functions (`sha256_pow_check`, `sha256_pow_solve`) have been removed.
They provided an insecure fallback path that could be exploited to bypass GPU/ASIC-resistant Argon2id
memory-hard PoW. If Argon2id memory allocation fails, the operation fails hard.

---

**Adding a new message type:**

1. Add the variant to `MessageType` in `protocol/src/envelope.rs`.
2. Add a constructor if needed.
3. Handle the new type in the appropriate handler (`relay/src/main.rs`,
   `dht-core/src/dht_node.rs`, `p2p/src/peer.rs`).

---

### `nullnode-crypto` — Kyber-768 KEM encryption, forward secrecy, and key persistence

**ALL user messages use Kyber-768 KEM (ML-KEM, NIST Level 3). There is NO classical fallback.**

```rust
// Encrypt plaintext for a recipient using Kyber-768 KEM (mandatory)
// Generates ephemeral keypair, encapsulates shared secret, derives AES key via HKDF
encrypt(plaintext: &str, recipient_kyber_enc: &KyberEncapsulationKey) -> Result<String, CryptoError>

// Decrypt ciphertext using our Kyber-768 decapsulation key
decrypt(ciphertext_hex: &str, our_kyber_dec: &KyberDecapsulationKey) -> Result<String, CryptoError>
```

**KyberKeypair persistence (G10):**

```rust
// Generate a new keypair
KyberKeypair::generate() -> Result<KyberKeypair, CryptoError>

// Save to file (hex-encoded JSON, 0o600 permissions)
kp.save(path: &Path) -> Result<(), CryptoError>

// Load from file
KyberKeypair::load(path: &Path) -> Result<KyberKeypair, CryptoError>

// Load or generate (convenience method)
KyberKeypair::load_or_generate(path: &Path) -> Result<KyberKeypair, CryptoError>
```

**DoubleRatchetSession (Kyber-768 KEM + forward secrecy + persistence):**

```rust
// Initialize a new session with paired fingerprints
DoubleRatchetSession::new(peer_fp, peer_nid, our_fp, is_initiator) -> Result<Self, CryptoError>

// Encrypt a message: fresh ephemeral Kyber-768 keypair + chain key evolution
session.encrypt_message(plaintext: &str, peer_kyber_enc: &KyberEncapsulationKey) -> Result<String, CryptoError>

// Decrypt a message: decapsulate Kyber ciphertext + chain key evolution
session.decrypt_message(message: &str, our_kyber_keypair: &KyberKeypair) -> Result<String, CryptoError>

// Persistence (G9): save/load session state to/from JSON file
session.serialize() -> Result<String, CryptoError>
DoubleRatchetSession::deserialize(json: &str) -> Result<Self, CryptoError>
session.save(path: &Path) -> Result<(), CryptoError>
DoubleRatchetSession::load(path: &Path) -> Result<Self, CryptoError>

**KEM-then-AEAD construction:**
1. Generate fresh ephemeral Kyber-768 keypair per message
2. Encapsulate shared secret with recipient's static public key
3. Combine shared secret with ratchet chain key via SHA-256
4. Derive AES-256-GCM key via HKDF-SHA256
5. Wire format: `ephemeral_pk (1184B) || kyber_ct (1088B) || nonce (12B) || aes_ct`

**Design rules:**

1. `encrypt()` and `decrypt()` return `CryptoResult` — callers must handle errors.
2. Ratchet state can be persisted via `save()`/`load()` for session survival across restarts.
3. Key derivation uses HKDF-SHA256.
4. All random values use `rand::thread_rng()` (cryptographic).
5. **NO classical fallback** — Kyber-768 KEM is mandatory for all user messages.
6. Each message uses a unique ephemeral keypair (forward secrecy).
7. Kyber keys are persisted with 0o600 permissions (owner-only read).
8. Persistence files use JSON format for auditability.

---

### `nullnode-crypto-utils` — OpenPGP and secure utilities

In-process Sequoia OpenPGP operations (no shell-out to gpg binary).

```rust
// OpenPGP operations (Sequoia in-process)
export_pubkey() -> CryptoUtilsResult<String>              // Armor the cert
import_pubkey(armored: &str) -> CryptoUtilsResult<String> // Import cert, returns fingerprint
get_fingerprint_from_armored(armored: &str) -> CryptoUtilsResult<String>  // Extract fingerprint
get_own_fingerprint() -> CryptoUtilsResult<String>         // Read own cert from disk

// Fingerprint and Null ID utilities
validate_fingerprint(fp: &str) -> bool                    // 32 or 40 hex chars
null_id_from_fingerprint(fp: &str) -> String              // NN-XXXX-XXXX via SHA-256

// Secure file deletion (overwrite with random, fsync, unlink)
secure_delete(path: &str) -> CryptoUtilsResult<()>
```

**Design rules:**

1. All OpenPGP operations use the Sequoia OpenPGP library (in-process, no shell-out).
2. Fingerprints must be validated (32 or 40 hex chars) before use.
3. Certs are cached in dht-core and relay for TOFU-based verification.
4. `secure_delete` is best-effort (CoW filesystems may not fully erase).

---

### `nullnode-dht-core` — Kademlia DHT node

```rust
// Configuration
NodeConfig {
    null_id: String,          // NN-XXXX-XXXX
    fingerprint: String,      // GPG fingerprint
    host: String,
    port: u16,
    db_path: Option<String>,  // SQLite file
    // ... more fields
}

// Async runtime
DhtNodeRuntime::new(config).await -> Self
runtime.start().await -> Result<()>

// Storage (via nullnode-dht-core/sqlite_store.rs)
DhtStore::new(path: &str) -> Self
store.put(key, value, salt, seq, publisher_fp, ttl) -> Result<()>
store.get(key) -> Option<KvRecord>

// TOFU pinning
pin_get(null_id: &str) -> Option<String>
pin_update(null_id: &str, address: &str) -> Result<()>
pin_verify_address(null_id: &str, address: &str) -> bool

// Certificate verification (bootstrap TLS)
verify_bootstrap_cert(seed_url: &str, pin_cache: &Path) -> Result<CertInfo>
bootstrap_pin_check(seed_url: &str, cert_fp: &str, not_before: &str, not_after: &str) -> bool
/// SECURITY NOTE (G4): First-time bootstrap pins log a warning to alert users
/// about TOFU trust decisions.

// Domain/cert validation helpers (public)
domain_matches(cert_domain: &str, pattern: &str) -> bool
cert_has_trusted_domain(cert_info: &CertInfo) -> bool
cert_issuer_is_trusted(cert_info: &CertInfo) -> bool

// Constant-time comparison (prevents timing attacks on fingerprint comparison)
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

**Address ownership verification (dht-addr-record):**
```
Publisher signs: null_id|address|ttl
Signature verified against publisher's OpenPGP cert (in-process via Sequoia)
null_id must equal compute_null_id(publisher_fp)  (proves key ownership)
Stored in DHT with salt prefix "addr:" to distinguish from mailbox data
```

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
- TOFU pinning prevents DHT address spoofing MITM
- Rate limiting: connection (50/60s), query (200/60s), max value size (1KB)
- SECURITY FIX (G7): Fingerprint sanitized before filesystem use to prevent path traversal
- SECURITY FIX (G9): Rate limiter capped at 100k buckets to prevent memory exhaustion
- SECURITY FIX (G8): Session serialization includes pending ciphertext (necessary for reliability);
  stored with 0o600 permissions. Consider encrypted filesystem for high-security.
- SECURITY FIX (G10): PoW parameters validated (nonce range, difficulty) before hashing.

---

### `nullnode-p2p` — P2P client node

```rust
// Configuration
P2pConfig {
    nid: String,
    fingerprint: String,
    bootstrap: Vec<String>,
    transport: TransportConfig,
}

// Peer node
P2pNode::new(config) -> Self
node.start().await -> Result<()>
node.send_message(peer_nid, peer_fp, text) -> Result<bool>
```

**Transport layer (`p2p/src/tor.rs`, `p2p/src/transport.rs`):**

```rust
TransportConfig {
    use_tor: bool,
    tor_socks_host: String,
    tor_socks_port: u16,
    tor_control_port: u16,
    tor_control_password: String,
    onion_port: u16,
    onion_address: String,  // pre-configured fallback
}

// Hidden service manager
TorHiddenServiceManager::new(config) -> Self
manager.start() -> String       // returns .onion address (or empty)
manager.stop()                  // cleanup
manager.is_available() -> bool   // Tor SOCKS reachable?
manager.get_onion_address() -> String

// Helpers
build_onion_uri(onion: &str, port: u16) -> String   // wss://{onion}:{port}
is_onion_address(addr: &str) -> bool
normalize_peer_address(addr: &str, config) -> String
transport_from_env() -> TransportConfig   // reads NULLNODE_* env vars
```

**NAT traversal (`p2p/src/nat.rs`):**

```rust
// STUN-based public endpoint discovery
StunProtocol::new(host: &str, port: u16) -> Self
protocol.get_public_endpoint() -> Result<(String, u16)>
protocol.parse_response(data: &[(u8, SocketAddr)]) -> Option<(String, u16)>

// UDP hole punching
hole_punch(local_port: u16, peer_ip: &str, peer_port: u16) -> Option<UdpSocket>

// Tor connection
connect_through_tor(socks_addr: &SocketAddr, target_host: &str, target_port: u16)
    -> MaybeTlsStream<TcpStream>
```

**Design rules:**

1. When `use_tor=True`, ALL outgoing connections go through the Tor SOCKS proxy.
2. When Tor is enabled, the listener binds on `127.0.0.1` (Tor connects via hidden service).
3. The `.onion` address is self-authenticating (derived from ed25519 key).
4. Pin cache at `~/.nullnode/bootstrap_pin_cache.json`.
5. STUN is optional; Tor removes the need for public endpoint discovery.

---

### `nullnode-relay` — WebSocket relay server

Binary crate producing `nullnode-relay`.

```rust
// CLI: --host, --port, --peer, --secret
// Main loop accepts WebSocket connections and routes messages
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
  2. Verify sender OpenPGP signature over canonical data (Sequoia in-process)
  3. Check timestamp freshness (replay protection)
  4. Check and record nonce (replay protection)
  5. Store in recipient's mailbox (per-sender cap: 10, global: 1000)
  6. If recipient in remote_routes -> relay-forward to peer relay

relay-fetch (client -> relay):
  1. Verify OpenPGP signature proving requester owns identity (Sequoia in-process)
  2. Verify null_id matches fingerprint derivation
  3. Check nonce replay
  4. Verify HMAC if shared secret configured
  5. Return mailbox entries (TTL 7 days)

route-advertise (relay -> relay):
  1. Update remote_routes with advertised Null IDs
  2. Update peer last_seen timestamp
  3. Respond with route-advertise-ack containing our local Null IDs

relay-forward (relay -> relay):
  1. Verify inner GPG signature
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

Binary crate producing `nullnode`.

```rust
// Commands
cmd_init(config)       // Generate identity
cmd_id(config)         // Show Null ID + fingerprint
cmd_export()           // Print armored public key
cmd_import(armored)    // Import from file or stdin, returns fingerprint
cmd_contacts()         // List registered contacts
cmd_add_contact(nid, fp) // Add a contact with fingerprint
cmd_send(nid, msg)     // Send message to peer (DHT lookup + P2P delivery)
cmd_read()             // Read messages from relay mailbox
cmd_listen(config)     // Start P2P listener for incoming connections
cmd_chat(nid)          // Interactive P2P chat
cmd_verify(nid)        // Verify contact safety number (G6)
cmd_safety_number(nid) // Show safety number for a contact (G6)
cmd_status()           // Show DHT status
```

**Configuration paths:**

| Path | Purpose |
|---|---|
| `~/.nullnode/identity.json` | Own Null ID + fingerprint |
| `~/.nullnode/contacts.json` | NID -> fingerprint mapping |
| `~/.nullnode/pin_cache.json` | DHT address TOFU pins |
| `~/.nullnode/bootstrap_pin_cache.json` | Bootstrap TLS cert TOFU pins |
| `~/.nullnode/dht_store.db` | SQLite DHT storage |
| `~/.nullnode/messages.db` | SQLite message store (G5) |
| `~/.nullnode/kyber_keys.json` | Persisted Kyber keypair (G10) |
| `~/.nullnode/ratchet_sessions/` | Persisted ratchet sessions (G9) |

---

### `nullnode-bootstrap` — Bootstrap DHT server

Binary crate producing `nullnode-bootstrap`.

```rust
// CLI: --host, --port, --id, --db
// Starts a DHT WebSocket server on the specified port
// Stores data in SQLite at the specified path
```

---

## Testing

```bash
# Run all tests (33 tests)
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
| `nullnode-protocol` | 9 | PoW solve/check, envelope roundtrip, GPG sign/verify |
| `nullnode-p2p` | 2 | Transport, handshake |
| `nullnode-dht-core` | 17 | DHT node, SQLite, ratelimit, pin_cache, bootstrap_verify |
| `nullnode-crypto` | 11 | encrypt/decrypt, ratchet, key derivation, kyber persistence |
| `nullnode-crypto-utils` | 4 | export/import, fingerprint validation, secure_delete |
| `nullnode-relay` | 11 | URL parse, HMAC, route table, nonce replay, loop detection |
| **Total** | **54** | |

---
---

## ACS2.6 Compliance Status

See `FEATURES.md` for full compliance matrix. Key implementation notes:

| ACS2.6 Feature | Implementation Status | Notes |
|----------------|---------------------|-------|
| Memory Protection | ✅ Implemented | `crypto/src/secure_mem.rs` provides `secure_zero_memory`, `lock_memory`, `SecureKeyMaterial` |
| ML-KEM Braid | ❌ Not implemented | Uses monolithic Kyber-768 key exchange (no chunking) |
| Delivery Tokens | ❌ Not implemented | Sender identity exposed in handshake (known limitation) |
| Hardware Attestation | ❌ Not implemented | Requires SEV-SNP/TDX platform support |
| CBNP | ❌ Not implemented | No synthetic dummy traffic loops |
| ML-KEM-1024 | ⚠️ Variant mismatch | Currently uses MlKem768 (NIST Level 3) vs ML-KEM-1024 (NIST Level 5) |

---
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
| `target/release/nullnode` | ~2 MB | CLI client |
| `target/release/nullnode-relay` | ~2 MB | Relay server |
| `target/release/nullnode-bootstrap` | ~4 MB | Bootstrap DHT server |

---

## Security considerations

1. **No automatic trust** — keys must be explicitly trusted after out-of-band verification.
2. **Safety number verification** (G6) — deterministic safety number derived from both parties' fingerprints enables out-of-band key verification.
3. **Constant-time comparison** — used for fingerprint comparison to prevent timing attacks.
4. **Secure deletion** — temp files overwritten with random bytes before unlink.
5. **TOFU pinning** — first-seen addresses and TLS certs are pinned to disk.
6. **Rate limiting** — prevents DoS and spam on DHT and relay.
7. **Tor support** — optional IP masking for all network traffic.
8. **Bootstrap verification** — TLS cert domain, CA, and TOFU checks prevent rogue servers.
9. **PoW anti-spam** — Argon2id memory-hard puzzles make bulk abuse infeasible.
10. **Key persistence** — All persisted keys and sessions use 0o600 permissions (owner-only).
11. **Double ratchet** — Forward secrecy with per-message key derivation; sessions now persist across restarts.
12. **Signed P2P handshake** — All P2P hello, hello-ack, message, and ack messages are GPG-signed to prevent MITM attacks.
13. **Signature verification** — Incoming P2P messages verify sender signature before processing.
14. **Encrypted message storage** — SQLite database stores only ciphertext; no plaintext ever written to disk (HIGH-4).

---

## Relay Federation

Multi-relay federation allows messages to route between relay servers:

1. **Peer connections** — `connect_to_peer()` maintains persistent WebSocket connections to peer relays with sender/receiver tasks
2. **Route advertisement** — `gossip_task()` periodically advertises known null_ids to connected peers via route-advertise messages
3. **Cross-relay forwarding** — `forward_to_peer()` sends relay-forward messages to peer relays when the recipient is not local
4. **Route lookup** — The relay uses `FederationState::lookup_route()` to determine which peer serves a given null_id
5. **HMAC optional auth** — Federation can use shared-secret HMAC for peer authentication (optional)

**Known limitation**: Federation currently requires manual peer URL configuration via command-line.
Automatic peer discovery will be implemented in a future phase.

---

## License

Business Source License (BSL / BUSL).
You can use the code for free if your company or organisation doesn't have more than 2 people.
