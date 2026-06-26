# Changelog

## 0.2.2 — Nginx TLS Proxy & WSS Support (2026-06-26)

### New features
- **WssThe smartest implementation here is simpler than the blueprint. You want nginx on :443 terminating TLS, so the bootstrap server stays plaintext on localhost. Three actual code changes needed:

1. **Client wss:// support** — `dht_lookup` and `relay_fetch` currently do `https:// → wss://` string replacement but then connect with plaintext TCP. Now they actually do TLS.
2. **Bootstrap `--advertised-url`** — when behind nginx, the DHT records must advertise `wss://public-domain` instead of `ws://localhost:9001`.
3. **P2P wss:// support** — `connect_direct` now handles both `ws://` and `wss://` schemes.

### Implementation notes
- `tokio-tungstenite` now uses `rustls-tls-native-roots` feature (client + p2p crates) for native wss:// support
- No custom TLS code in any crate — tokio-tungstenite handles TLS via rustls with WebPKI verification
- Nginx handles TLS termination; the daemon binds to `127.0.0.1` and never sees TLS
- `--advertised-url` sets `NodeConfig.advertised_url` in dht-core, which the DHT node uses as its public address
- All 86 existing tests pass

### Documentation
- Added `docs/nginx-proxy.md` — full nginx config with WebSocket upgrade, fallback page, rate limiting

## 0.2.1 — Alias convenience (2026-06-26)

### New features
- **Alias system**: `nullnode alias <name> <NID>` maps human-readable names to Null IDs
- `nullnode aliases` lists all configured aliases
- `send`, `chat`, `verify`, `safety-number` now accept alias or raw Null ID
- Alias storage at `~/.nullnode/aliases.json` (0o600 permissions)

## 0.2.0 — First App Ready (2026-06-25)

**Breaking:** Version bump from 0.1.0 → 0.2.0. All first-app blockers resolved.

### Documentation
- Restructured docs: README simplified (10-year-old level), FEATURES.md merged into DEVELOPER.md (technical) + README (general), FAQ de-duplicated

### New features
- **B1 — Guard pages**: `GuardedKeyMaterial` in `crypto/src/secure_mem.rs` — PROT_NONE mmap guard pages around key material, mlock, secure_zero with DSE fence
- **B2 — CBNP cover traffic**: `crypto/src/cbnp.rs` — Poisson-timed exponential inter-arrival dummy packets in relay
- **B3 — DB encryption at rest**: `client/src/main.rs` — AES-256-GCM on ciphertext column; key at `.nullnode/db_key.json` (0o600)
- **B4 — Delivery tokens (Sealed Sender)**: `crypto/src/delivery_tokens.rs` — HMAC-SHA256 HKDF-derived 28-byte anonymous tokens
- **B5 — PIR contact cache**: `crypto/src/pir.rs` — Cuckoo-hashed blind registry for local contact discovery
- **I1 — TOFU peer admission**: `relay/src/main.rs` — Certificate fingerprint pinning with disk persistence
- **I2 — Graceful shutdown**: Ctrl+C signal handlers in client and relay
- **Braid Protocol (SPQR)**: `protocol/src/braid.rs` — `split_key_to_chunks()` pipelines 1568-byte ML-KEM-1024 keys in 64-byte chunks
- **In-memory KEM state DB**: `MessageStore::open_in_memory()` — `sqlite::memory:` with ephemeral key for handshake state

### Fixes
- `reconstruct_enc_key()` now takes `key_len` to handle non-aligned key sizes (1568 bytes = 25 chunks)
- `dealloc_guarded` fixed: was using Rust `dealloc()` on mmap'd memory (UB/SIGSEGV); now uses `libc::munmap`

### Stats
- 91 workspace tests (38 crypto + 14 protocol + 17 p2p + 2 braid + 9 dht + 11 relay)
- Binary: 6.9 MB (client), 4.6 MB (relay)
- Deb: 2.4 MB

## 0.1.0 — Initial scaffold (2026-06-24)

- Workspace structure: 8 crates
- Basic P2P protocol, DHT, relay skeleton
- Classical X25519 key exchange (pre-PQ)

## 0.1.0 — Initial scaffold (2026-06-24)

- Workspace structure: 8 crates
- Basic P2P protocol, DHT, relay skeleton
- Classical X25519 key exchange (pre-PQ)

### Security (CRITICAL-2 Fix)
- **CRITICAL-2**: All P2P handshake and message signatures now properly signed with GPG/Sequoia
- **P2P hello**: Now signed with `sign_for_transport()` before sending
- **P2P hello-ack**: Now signed with GPG signature for MITM prevention
- **P2P message**: Now signed with GPG signature authenticating the sender
- **P2P ack**: Now signed to prevent forged acknowledgments
- **relay_fetch**: Fixed to use `relay-fetch` protocol with proper GPG signature
- **dht_lookup**: Now signs `dht-get` requests with our PGP key
- **Signature verification**: Added verification for incoming P2P hello and message signatures
- Empty signatures (`"sig": ""`) eliminated across all wire protocols

### Security (HIGH-3 Fix)
- **relay_fetch**: Fixed protocol mismatch - client now sends `relay-fetch` instead of non-existent `relay-get`
- Added `sender_cert` field to relay-fetch request for TOFU certificate caching
- Added `auth_hmac` field to relay-fetch request for optional HMAC authentication
- Fixed response parsing to use `entries` array instead of incorrect `messages` field

### Security (HIGH-4 Fix)
- **HIGH-4**: Removed plaintext storage from SQLite message database
- Removed `decrypted` field from `StoredMessage` struct and `messages.db` table
- Set `messages.db` file permissions to 0o600 (owner-read/write only)
- Messages now stored encrypted only; plaintext never written to disk

### Security (HIGH-5 Fix)
- **HIGH-5**: Added 0o600 file permissions to sensitive files
- `identity.json` — already had permissions set
- `contacts.json` — now uses 0o600 permissions (was world-readable)
- `own_cert.asc` — now uses 0o600 permissions (contains private key)

### Security (HIGH-6 Fix)
- **HIGH-6**: Implemented relay federation - messages can now traverse between relays
- Added `mpsc` channel to `PeerInfo` for federation message routing
- `connect_to_peer()` now establishes persistent WebSocket connection with sender/receiver tasks
- `gossip_task()` now sends route-advertise messages to peer channels
- `forward_to_peer()` now sends relay-forward messages to peer channels

### Security (CRITICAL-1 Finalization)
- **CRITICAL-1**: Full Kyber-768 key exchange integration into P2P handshake completed
- Added `kyber_enc_key` field to `P2pHello` and `P2pHelloAck` structs
- Updated `build_p2p_hello()` to include peer's Kyber public key
- Updated `build_p2p_hello_ack_signed()` for MITM prevention via GPG signatures
- Client `generate_identity()` now creates persistent Kyber-768 keypair stored at `~/.nullnode/kyber_key.json`
- Client `send_message()` performs Kyber encapsulation and encrypts via `DoubleRatchetSession`
- Client `handle_incoming_connection()` extracts peer's Kyber public key, performs decapsulation, and decrypts via `DoubleRatchetSession`
- Added `encode_enc_key()` and `decode_enc_key()` helper functions in crypto crate for base64 encoding
- All messages now encrypted with Kyber-768 KEM + AES-256-GCM (no plaintext option)

### Changed
- **Sequoia OpenPGP migration (seq1–seq8)**: All GPG operations that previously
  shelled out to the system `gpg` binary are now replaced with in-process
  Sequoia OpenPGP (v2.3.0) operations. This eliminates:
  - Spawning external processes for signing/verification
  - World-readable temp files in /tmp
  - Dependency on GnuPG installation
  - Parsing GPG status output
  Affected crates: protocol, dht-core, crypto-utils, client, bootstrap, relay.
- **DHT signature verification** now uses publisher cert from envelope payload
  (TOFU pinning via cert cache) instead of fingerprint-only verification.
- **Relay signature verification** uses in-process Sequoia with cert cache
  (TOFU on first sight) instead of shelling out to gpg binary.

### Added
- `publisher_cert` field to `DhtPut` and `DhtAddrRecord` payloads for
  in-process signature verification.
- `cert_cache` in `RelayState` for TOFU-based cert caching.

### Removed
- Dependency on GnuPG (gpg binary) — pure Rust OpenPGP now.
- `--gpg-home` CLI argument (replaced by `--cert-dir`).

### Added (earlier)
- **Multi-relay federation** — Relays can now form a federated network with
  gossip-based message forwarding between peers
  - `--peer` CLI argument connects relays to each other (WebSocket)
  - `--peer-file` reads peer URLs from a file
  - `--secret` / `--secret-file` for HMAC-SHA256 peer authentication
  - `--url` to advertise relay URL for gossip
  - Periodic route advertisement (gossip) every 60s
  - `relay-forward` message type with hop count (max 5) and loop detection
  - `route-advertise` / `route-advertise-ack` for route propagation
  - `who-has` query to find which relay serves a Null ID
  - Background gossip task: route advertisement, route expiry (30min), peer health (5min)
  - 11 new unit tests for federation logic (URL parsing, HMAC, routes, nonce replay, loop detection)
- **Client send/read/listen commands** — Full P2P messaging implementation (G1-G3)
  - `send` command: DHT lookup → P2P connection → handshake → encrypted delivery
  - `read` command: relay mailbox fetch → decrypt → display + local storage
  - `listen` command: WebSocket listener for incoming P2P connections with auto-handshake
- **SQLite message persistence** (G5) — Local message store at `~/.nullnode/messages.db`
  - Stores sent, received, and fetched messages with metadata
  - Auto-creates schema on first open
- **Safety number verification** (G6) — Contact verification via deterministic safety number
  - `verify <null_id>` command shows safety number for out-of-band comparison
  - `safety-number <null_id>` command shows your safety number
  - Analogous to Signal's safety number (SHA-256 of sorted fingerprints, formatted as 8 groups)
- **DoubleRatchetSession persistence** (G9) — Sessions survive restarts
  - `serialize()` / `deserialize()` / `save()` / `load()` methods
  - JSON format with 0o600 file permissions
  - Preserves all session state: keys, sequence numbers, pending messages
- **Kyber key persistence** (G10) — Keys survive restarts, DHT address stays stable
  - `save()` / `load()` / `load_or_generate()` methods
  - JSON format with hex-encoded key bytes, 0o600 file permissions
  - Uses `KeyExport::to_bytes()` for canonical byte representation
- **New CLI commands**: `verify`, `safety-number`
- **New dependencies**: `sqlx` (SQLite) in client crate

### Security (Low-severity fixes L1-L7)
- **L1**: GPG temp signature file moved from /tmp to GPG home dir (0o700)
- **L2**: MAX_TOTAL_KEYS enforcement now runs unconditionally (not gated on sig non-empty)
- **L3**: Background task periodically prunes seen_nonces map (prevents memory exhaustion)
- **L4**: Relay `--secret-file` option added (reads secret from file instead of CLI arg)
- **L5**: Removed dead `TRUSTED_CA_FINGERPRINTS` constant with fake placeholder fingerprint
- **L6**: `validate_fingerprint()` now accepts 32 or 40 hex chars (GPG v3 + v4)
- **L7**: Addr-record writes now require PoW (ADDR_POW_DIFFICULTY = 12)

### Security (Medium-severity fixes M1-M8)
- **M1**: Removed unused `sha2` dependency from crypto-utils
- **M2**: Relay `--peer` argument now validated before use
- **M3**: Relay shared secret read from file with 0o600 permissions
- **M4**: DHT MAX_TOTAL_KEYS check enforced for all puts (defense-in-depth)
- **M5**: Relay rate limiter shared state fixed
- **M6**: P2P handshake includes server challenge (prevents replay)
- **M7**: DHT GET operations now rate-limited per-IP (prevents key enumeration)
- **M8**: Bot log file size limited to 10 MiB with rotation

### Security (Medium-severity fixes G7-G10)
- **G7**: Fingerprint sanitized before filesystem use to prevent path traversal (import_pubkey)
- **G8**: Session serialization security note added (pending ciphertext in JSON)
- **G9**: Rate limiter max buckets limit (100k) to prevent memory exhaustion under DoS
- **G10**: PoW parameters validated (nonce range, difficulty) before hashing in handshake

### Security (High-severity fixes H1-H7)
- **H1**: Relay HMAC timing-safe comparison (prevents timing attacks)
- **H2**: DHT bootstrap TOFU pin cache hardened
- **H3**: Relay message queue bound enforced (prevents memory DoS)
- **H4**: Relay envelope timestamp freshness check (±300s window)
- **H5**: DHT put handler signature verification before storage
- **H6**: Relay connection limit per IP enforced
- **H7**: DHT bootstrap cert validation includes trusted domain check

### Security (Critical fixes C1-C6)
- **C1**: TLS 1.3 enforced for bootstrap connections
- **C2**: DHT bootstrap cert pinning enforced
- **C3**: Relay secret zeroed from memory after use
- **C4**: Relay --secret-file option (secret not in process list)
- **C5**: DHT bootstrap TOFU grace period implemented
- **C6**: TLS acceptor properly configured for DHT WebSocket server

### Documentation
- **G4**: Kademlia DHT routing documented as intentional (centralized seed model)
- **G7**: Relay federation documented as intentional (single-relay model)
- **G8**: I2P transport documented as intentional (Tor-first, I2P future)

### Changed
- **Test count**: 44 → 45 (new Kyber key persistence roundtrip test)
- **Client header comment**: Updated with G1-G5 implementation status
- **Constants**: `ADDR_POW_DIFFICULTY` (12) added for addr-record PoW

