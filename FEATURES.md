# NullNode Features & Setup Guide

## What is NullNode?

NullNode is a peer-to-peer encrypted messenger. There is no central server
that reads your messages. Messages are encrypted with ML-KEM-1024 KEM (NIST
Level 5, FIPS 203 compliant) — there is NO classical fallback. Users may
optionally select ML-KEM-768 (NIST Level 3) for reduced bandwidth. All user
messages use a "KEM-then-AEAD" construction: a fresh ephemeral ML-KEM
keypair per message encapsulates a shared secret, which encrypts the actual
message payload via AES-256-GCM (forward secrecy + replay protection).

If both people are online, messages flow directly between them. If the
recipient is offline, messages are stored encrypted in the DHT and retrieved
when they come back online.

---

## Current Features

### Cryptography

- **Kyber-768 KEM (ML-KEM, mandatory)**: ALL user messages use Kyber-768
  post-quantum key encapsulation. There is NO classical fallback — no X25519,
  no AES-only path. Kyber-768 is NIST Level 3 / FIPS 203 compliant.
- **KEM-then-AEAD construction**: Each message generates a fresh ephemeral
  Kyber-768 keypair. The shared secret from KEM encapsulation is combined with
  a ratchet chain key (SHA-256), then HKDF-SHA256 derives an AES-256-GCM key.
  The wire format carries: ephemeral_pk || kyber_ciphertext || nonce || aes_ciphertext.
- **Forward secrecy**: Double ratchet with per-message ephemeral Kyber keys
  + HKDF-SHA256 chain key evolution. Each message uses a fresh key derivation
  step. If your long-term key is compromised, past messages remain unreadable
  and future messages recover after the next ratchet step.
- **Anti-replay**: Timestamps (5-minute clock skew tolerance) + sequence
  numbers prevent message replay. Skipped-key tracking with DoS cap (256).
- **Identity binding**: Your Null ID (NN-XXXX-XXXX) is a one-way BLAKE2b-8
  hash of your public key. No one can claim your identity without your key.
- **Explicit trust**: Keys must be manually trusted before use. No automatic
  trust, no trust bypass. Trust stored in `~/.nullnode/trust_map.json`.
- **Message signing**: All P2P handshake and DHT write operations are signed
  with the sender's Ed25519 key for authenticity.

### Network

- **Peer-to-peer messaging**: Direct WebSocket connections when both peers
  are online. Handshake with proof-of-work + signature verification.
- **Client commands**: `send` (DHT lookup + P2P delivery), `read` (relay mailbox
  fetch + decrypt), `listen` (WebSocket listener for incoming connections).
- **DHT mailbox (store-and-forward)**: Encrypted messages stored in a
  Kademlia-style DHT when the recipient is offline. Retrieved on reconnect
  (polled every 30s).
- **Proof-of-work anti-spam**: Every DHT write requires solving an
  Argon2id memory-hard puzzle (~0.5s on modern CPU, 16MB memory cost).
  P2P handshakes use a lighter puzzle (difficulty 12, ~0.1s, 1MB memory).
  Address records use difficulty 12 (~0.1s, 1MB memory).
  Argon2id is GPU/ASIC-resistant: a 24GB GPU can only run ~1500 parallel
  instances, reducing botnet throughput by ~500,000x vs SHA-256 hashcash.
- **NAT traversal**: STUN protocol + UDP hole punching for clients behind
  home routers. Multiple STUN servers tried with retries.
- **Bootstrap DHT seeds**: 3 bootstrap nodes help you join the network.
  They never see message content or metadata. Bootstrap servers speak TLS
  directly (no reverse proxy needed).
- **Stealth mode**: Set `NULLNODE_STEALTH=true` to return ambiguous responses
  to non-client connections. Port scanners and bots receive "HTTP/1.1 400 Bad
  Request" or empty responses instead of "dht-error" JSON, making fingerprint
  identification harder.
- **Tor transport (optional)**: Route all traffic through the Tor network to
  hide your IP address. When enabled, NullNode creates a Tor hidden service
  (v3 .onion address) and advertises it in the DHT instead of an IP address.
  All outgoing connections (P2P, DHT bootstrap, mailbox polling) go through
  the Tor SOCKS5 proxy. Activate with `--tor` flag or `NULLNODE_USE_TOR=true`.
  Requires a running Tor daemon with control port.
- **I2P transport**: Not implemented (documented as intentional G8). The
  project follows a Tor-first approach. I2P support is planned as a future
  transport option but requires additional dependencies and architectural changes.

### Storage

- **Persistent DHT storage**: SQLite-backed message store on each DHT node
  (`~/.nullnode/dht_store.db`, WAL mode).
- **Local message store**: SQLite-backed message history on the client
  (`~/.nullnode/messages.db`, auto-created schema). Stores sent, received,
  and fetched messages with full metadata. All messages stored encrypted;
  no plaintext ever written to disk (HIGH-4).
- **TTL-based expiry**: Address records expire after 2h, mailbox messages after 7 days.
- **Key persistence**: Kyber-768 keypairs persist to disk (`~/.nullnode/kyber_keys.json`)
  so the DHT address remains stable across restarts. Double ratchet sessions
  persist to `~/.nullnode/ratchet_sessions/` for conversation continuity.
  All key files use 0o600 permissions (owner-only read).

### Security hardening

- **Safety number verification (G6)**: Deterministic safety number derived from
  both parties' fingerprints (SHA-256 of sorted fingerprints, formatted as 8 groups
  of 8 hex chars). Enables out-of-band key verification to detect MITM attacks.
  `verify` and `safety-number` CLI commands display the safety number for comparison.
- **DHT address ownership verification**: Address records in the DHT are
  signed by the publisher's OpenPGP key (in-process via Sequoia). The signature covers `null_id|address|ttl`,
  proving the publisher owns the private key for that null_id. Prevents DHT
  address spoofing MITM attacks.
- **TOFU pinning**: First address received for a null_id is trusted and pinned
  to disk (`~/.nullnode/pin_cache.json`). Subsequent addresses must match the
  pin -- mismatches are rejected with a warning (possible MITM).
- **Constant-time comparison**: All security-sensitive comparisons use
  constant-time comparison to prevent timing attacks.
- **Secure temp file handling**: Signature verification uses temp files in
  0700 directories, overwritten with random bytes before deletion.
- **Rate limiting**: Connection (50/60s) and message (120/60s) rate limits
  per source IP. Global queue cap (10,000). Max 10 sessions per Null ID.
  Per-IP GET rate limiting prevents key enumeration attacks.
- **Input validation**: All fingerprints, null IDs, and message sizes are
  validated before processing. Fingerprints accept 32 or 40 hex chars
  (GPG v3 + v4 compatibility).
- **Timestamp freshness**: DHT and P2P envelopes rejected if timestamp is
  too far from local clock (5-minute window). Relay enforces ±300s window.
- **Bootstrap server identity verification**: Client verifies bootstrap server's
  TLS certificate on every connection. Checks: cert fingerprint (TOFU pin),
  cert validity window (90-day rotation cycle), trusted domain (*.gnoppix.org
  or *.gnoppix.com), trusted CA (Let's Encrypt). Rogue bootstrap servers are
  rejected even with a valid cert for our domain from a compromised CA.
- **Bot/scanner detection**: Suspicious connections logged to `bot_connection.log`
  in the application directory. Detects port scanners, vulnerability probes,
  and misconfigured clients (bad envelopes, stale timestamps, unknown types).
- **Key file permissions**: All persisted keys, sessions, and secrets use 0o600
  permissions (owner-only read). Relay `--secret-file` reads from file instead
  of CLI argument to avoid exposure in process list.

---

## Architecture

```
+-----------------------------------------------------------+
|                   NullNode P2P Network                     |
|                                                           |
|  +----------+   DHT lookup   +----------+                |
|  |  Alice   |--------------->|   DHT    |                |
|  |  Client  |                | Network  |                |
|  +----+-----+                +----+-----+                |
|       | direct P2P (when online)  |                      |
|       |<------------------------->|                      |
|       |                           |                      |
|  +----+-----+   store-and-  +----+-----+                |
|  |   Bob    |   forward     |  DHT     |                |
|  |  Client  |<--------------|  Node    |                |
|  +----------+  (when offline)+----------+                |
|                                                           |
|  Client commands: send, read, listen, chat, verify        |
|  (G1-G3: DHT+P2P send, relay mailbox read, P2P listen)   |
|  (G5: SQLite message persistence)                         |
|  (G6: Safety number verification)                         |
|                                                           |
|  Bootstrap seeds (join only, no message handling):        |
|  wss://bootstrap-eu.gnoppix.org:9001                      |
|  wss://bootstrap-us.gnoppix.org:9001                      |
|  wss://bootstrap-asia.gnoppix.org:9001                    |
|                                                           |
||  Legacy relay (fallback only):                            |
||  ws://127.0.0.1:8765                                      |
||                                                           |
||  Federated relays (multi-relay):                           |
||  +--------------+    gossip    +--------------+            |
||  |  Relay Alpha |<----------> |  Relay Beta  |            |
||  |  relay-a.net |  route-adv  |  relay-b.net |            |
||  +--------------+             +--------------+            |
||  Messages forwarded via relay-forward (max 5 hops)         |
||  Peer auth via HMAC-SHA256 challenge-response             |
+-----------------------------------------------------------+
```

### Message flow (both online)

1. Alice looks up Bob's address in the DHT
2. Alice verifies the address record signature (proves Bob owns the key)
3. Alice checks TOFU pin -- rejects if address doesn't match pin
4. Alice connects directly to Bob via WebSocket
5. Both sides perform a handshake with proof-of-work + signature
6. Messages encrypted via double ratchet, sent directly
7. Each message acknowledged with hash verification

### Message flow (Bob offline)

1. Alice looks up Bob's address in the DHT (may be stale)
2. Alice tries direct connection -- fails
3. Alice encrypts message with Bob's public key
4. Alice stores encrypted blob in DHT at key `NN-BOB-ID`
5. Bob comes online, polls his DHT key every 30s
6. Bob retrieves and decrypts the message

---

## Setup

### Prerequisites

- Rust 1.75+ (2024 edition)
- Cargo
- Sequoia OpenPGP 2.3.0 (in-process OpenPGP, replaces shell-out to gpg binary)
- Tor daemon (optional, for IP masking)

### Build

```bash
cd rust
make all
```

### Create your identity

```bash
./target/release/nullnode init
```

Output:
```
identity created: NN-P4DM-WZPF
fingerprint: F5B0F201378A72EF973A88D170B7096AD5713AA7
```

Your Null ID is `NN-P4DM-WZPF`. This is what you share with others so they
can find and message you.

### View your identity

```bash
./target/release/nullnode id
```

### Export your public key

```bash
./target/release/nullnode export > mykey.asc
```

Share `mykey.asc` with people so they can import your key and message you.

### Import a peer's public key

```bash
./target/release/nullnode import theirkey.asc --alias NN-THEIR-ID
```

**IMPORTANT**: After importing, verify the fingerprint out-of-band (voice call,
in-person, etc.) before trusting it. Then set trust:

```bash
./target/release/nullnode contacts
```

### List contacts

```bash
./target/release/nullnode contacts
```

---

## Running a P2P Node (Client)

### Start listening for messages

```bash
./target/release/nullnode p2p --port 9001
```

This starts a P2P node that:
- Listens for incoming connections on port 9001
- Joins the DHT network via bootstrap seeds
- Advertises your address in the DHT
- Polls your DHT mailbox every 30s

### Send a message

```bash
./target/release/nullnode send NN-THEIR-ID "Hello, this is a secret message" --fingerprint THEIR_FP
```

The send command:
1. Looks up the recipient's address in the DHT
2. Establishes a direct WebSocket connection
3. Performs a handshake with proof-of-work + signature verification
4. Encrypts the message with Kyber-768 KEM + AES-256-GCM
5. Sends the encrypted payload and waits for acknowledgment
6. Falls back to DHT mailbox storage if the peer is unreachable

### Read messages

```bash
./target/release/nullnode read
```

The read command:
1. Connects to the relay WebSocket
2. Fetches messages from the relay mailbox
3. Decrypts each message using your Kyber-768 decapsulation key
4. Displays messages with sender info and timestamp
5. Stores messages in the local SQLite database

### Listen for incoming connections

```bash
./target/release/nullnode listen
```

### Interactive chat

```bash
./target/release/nullnode chat NN-THEIR-ID --fingerprint THEIR_FP
```

This opens an interactive session. Type messages, press Enter to send, type
`/quit` to exit.

### Verify a contact's safety number (G6)

```bash
./target/release/nullnode verify NN-THEIR-ID
```

Displays the safety number for out-of-band comparison with your contact.
Both parties should see the same 64-character hex string. If they differ,
a man-in-the-middle attack may be underway.

### DHT diagnostics

```bash
# Look up a peer's address
./target/release/nullnode dht --find NN-THEIR-ID

# Advertise your address
./target/release/nullnode dht --advertise "wss://your-public-ip:9001"
```

### Tor transport (IP masking)

```bash
# Route all traffic through Tor (requires Tor daemon running on 127.0.0.1:9050)
./target/release/nullnode p2p --port 9001 --tor

# Or via environment variable
export NULLNODE_USE_TOR=true
./target/release/nullnode p2p --port 9001

# Full Tor configuration
export NULLNODE_USE_TOR=true
export NULLNODE_TOR_SOCKS=socks5://127.0.0.1:9050
./target/release/nullnode p2p --port 9001
```

When Tor is enabled, NullNode will:
1. Route ALL outgoing connections through the Tor SOCKS5 proxy (NULLNODE_TOR_SOCKS)
2. Advertise the `.onion` address in the DHT instead of an IP (requires pre-configured NULLNODE_ONION_ADDRESS)
3. Incoming connections via Tor hidden services require manual configuration of your Tor daemon
4. The `.onion` address is self-authenticating (TOFU pinning is stronger than IP pinning)

---

## Running a Bootstrap DHT Seed (Server)

A bootstrap node is NOT a message relay. It only helps clients join the DHT
network. It never sees message content.

### Direct

```bash
./target/release/nullnode-bootstrap --host 0.0.0.0 --port 9001
```

### Bootstrap seed configuration

Clients connect to bootstrap seeds via the `NULLNODE_DHT_BOOTSTRAP` environment
variable or the `--bootstrap` flag:

```bash
export NULLNODE_DHT_BOOTSTRAP="wss://bootstrap-eu.gnoppix.org:9001,wss://bootstrap-us.gnoppix.org:9001"
```

Or run your own bootstrap and point clients to it:

```bash
export NULLNODE_DHT_BOOTSTRAP="wss://your-server:9001"
```

---

## Running a Relay (Federated Multi-Relay)

The relay supports **multi-relay federation** with gossip-based message forwarding.
Multiple relays can connect to each other to form a federated network, allowing
messages to reach recipients on any connected relay.

### Federation features

- **Peer connections**: Relays connect to each other via WebSocket (`--peer`)
- **Route advertisement**: Periodic gossip (every 60s) advertises local Null IDs
- **Hop-limited forwarding**: Messages can traverse up to 5 relay hops
- **Loop detection**: Via chain prevents infinite forwarding loops
- **HMAC authentication**: Shared secret authenticates peer relays
- **TTL-based route expiry**: Routes expire after 30 minutes

### Starting a federated relay

```bash
# Start relay with peer connections
./target/release/nullnode-relay --host 0.0.0.0 --port 8765 \
  --peer ws://relay-b.example.com:8765 \
  --peer ws://relay-c.example.com:8765 \
  --secret-file /path/to/shared_secret.txt

# Or read peers from a file
./target/release/nullnode-relay --host 0.0.0.0 --port 8765 \
  --peer-file /path/to/peers.txt
```

The relay is also a **fallback** for environments where P2P is not possible.
The primary architecture is P2P + DHT.

---

## Quick Start: Two Users

### Terminal 1: Alice

```bash
cd rust

# Create identity
./target/release/nullnode init
# -> identity created: NN-ALICE-ID
# -> fingerprint: AAAA...

# Export public key
./target/release/nullnode export > alice.asc

# Start P2P node
./target/release/nullnode p2p --port 9001
```

### Terminal 2: Bob

```bash
cd rust

# Create identity
./target/release/nullnode init
# -> identity created: NN-BOB-ID
# -> fingerprint: BBBB...

# Export public key
./target/release/nullnode export > bob.asc

# Import Alice's key
./target/release/nullnode import alice.asc --alias NN-ALICE-ID

# Set trust (after verifying fingerprint out-of-band!)
# Use the CLI or manually edit ~/.nullnode/contacts.json

# Start P2P node
./target/release/nullnode p2p --port 9002
```

### Terminal 1: Alice sends to Bob

```bash
./target/release/nullnode send NN-BOB-ID "Hello Bob!" --fingerprint BBBB...
```

Or interactive chat:

```bash
./target/release/nullnode chat NN-BOB-ID --fingerprint BBBB...
> Hello Bob!
> /quit
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NULLNODE_RELAY` | `ws://127.0.0.1:8765` | Legacy relay URL (fallback only) |
| `NULLNODE_DHT_BOOTSTRAP` | (3 built-in seeds) | Comma-separated bootstrap DHT seeds |
| `NULLNODE_USE_TOR` | `false` | Enable Tor transport (IP masking) |
| `NULLNODE_TOR_SOCKS` | `socks5://127.0.0.1:9050` | Tor SOCKS5 proxy address |
| `NULLNODE_ONION_ADDRESS` | (empty) | Pre-configured .onion address (required for Tor inbound) |
| `NULLNODE_ONION_PORT` | `9001` | Port for Tor hidden service |

---

## Security Checklist

Before relying on NullNode for sensitive communication:

- [ ] Verify peer fingerprints out-of-band (voice, in-person, etc.)
- [ ] Verify safety numbers match your contact's (G6 safety number verification)
- [ ] Set key trust to `ultimate` only after verification
- [ ] Run your own bootstrap seed if you don't trust the public ones
- [ ] Use a firewall to limit exposure of DHT port (6881) if needed
- [ ] Never share your secret key -- only export public keys
- [ ] Enable Tor if you need IP-level privacy
- [ ] Enable Tor if you need IP-level privacy

---

## ACS2.6 Specification Compliance

NullNode partially implements the Architectural & Cryptographic Specification v2.6. This section tracks compliance status.

### Part I: Core P2P Messaging & Metadata Protection

| ACS2.6 Requirement | Status | Notes |
|-----------------|--------|-------|
| **ML-KEM-1024** (instead of Kyber-768) | ✅ Complete | Uses `ml-kem 0.3.2` with MlKem1024 (NIST Level 5); dual-variant support (768/1024) via `MlKemVariant` config |
| **ML-KEM Braid Protocol (SPQR)** | ❌ Not implemented | No chunked key exchange / pipelining for large post-quantum keys |
| **Sealed Sender with Delivery Tokens** | ✅ Complete | `delivery_tokens` module: HMAC-SHA256-based token derivation (HKDF-like), constant-size 28-byte tokens, master secret regeneration, replay protection via token caching |
| **PQ-Sender Keys (Group Messaging)** | ❌ Not implemented | No group messaging support or ML-DSA-87 signing |
| **PIR Contact Discovery** | ✅ Complete | `pir` module: Blind registries with cuckoo hashing, XOR-masked bins, `PirRegistry` server-side + `PirClient` for private lookups. 4KB bins, 18 entries/bin, constant-size queries |

### Part II: Mobile, Bandwidth & Push Architecture

| ACS2.6 Requirement | Status | Notes |
|-----------------|--------|-------|
| **Adaptive Traffic Budgeting Engine** | ❌ Not implemented | No network state detection or Poisson streams |
| **PQ-PPN (Push Notifications)** | ❌ Not implemented | No push proxy or zero-knowledge triggers |

### Part III: Local Data-at-Rest Protection

| ACS2.6 Requirement | Status | Notes |
|-----------------|--------|-------|
| **Hardware-Bound Key Hierarchy** | ❌ Not implemented | No HSM integration or Argon2id user-derived keys |
| **Hardened SQLCipher (Page-Level Randomization)** | ⚠️ Partial | SQLite encrypted but no 4096B page randomization |
| **Memory Protection (mlock, secure_zero, guard pages)** | ✅ Implemented | See `crypto/src/secure_mem.rs` for `secure_zero_memory`, `lock_memory` |
| **Biometric Access Lifecycles** | ❌ Not implemented | No app lifecycle hooks for key scrubbing |

### Part IV: Network Resilience

| ACS2.6 Requirement | Status | Notes |
|-----------------|--------|-------|
| **DPI Evasion / Pluggable Transports** | ✅ Partial | TLS/WebSocket optional (`wss://`). Tor SOCKS5 support exists. |
| **Certificate-Based Core Node Admission** | ⚠️ Partial | GPG certificates used for signing but no mixnet admission control |

### Part V: Real-World Implementation Defenses

| ACS2.6 Requirement | Status | Notes |
|-----------------|--------|-------|
| **Coordinated Baseline Noise Protocol (CBNP)** | ✅ Complete | `cbnp` module: Poisson-timed cover traffic (exponential inter-arrival), 3200-byte dummy packets, burst mode, `is_cover_traffic()` detection. Configurable λ |
| **Bloom-Filtered Delta Syncing** | ❌ Not implemented | No compressed mailbox polling |
| **Guard Pages / VirtualLock** | ⚠️ Partial | mlock implemented but no guard pages around key pools |

### Part VI: Sovereign Infrastructure Hardening

| ACS2.6 Requirement | Status | Notes |
|-----------------|--------|-------|
| **Decentralized Hardware Attestation** | ❌ Not implemented | No REPORT_DATA binding, VCEK verification, or LAUNCH_MEASUREMENT checks |
| **Geopolitical Traffic Partitioning** | ❌ Not implemented | No jurisdiction-aware routing or WireGuard mesh tunnels |

---

## Currently Implemented Security Features

| Feature | ACS2.6 Mapped Requirement |
|---------|---------------------------|
| Kyber-768 KEM for key exchange | Part I.1 (variant: 768 vs 1024) |
| Double Ratchet with HKDF chain key | Part I.1 (partial) |
| Argon2id PoW (DHT: 16MB/3iter, P2P: 1MB/2iter) | Part I.5 anti-spam |
| HMAC federation authentication | Part I.4 (partial) |
| TLS/WebSocket transport (optional) | Part IV.1 DPI evasion |
| Tor SOCKS5 transport support | Part IV.1 DPI evasion |
| Sequoia in-process OpenPGP | Part III (signing/verification) |
| Rate limiting (connection + GET) | Part I.5 anti-abuse |
| Bot/scanner detection | Part V.4 security framework |

---

## Future Implementation Priority

1. **ML-KEM-1024 upgrade** - Higher security level (NIST Level 5)
2. **Memory protection** - `SecureKeyMaterial` integration for key persistence
3. **Delivery tokens** - Sealed sender metadata protection
4. **CBNP** ✅ - Synthetic background traffic to prevent cold-start correlation (`cbnp` module)
5. **PIR contact discovery** ✅ - Zero-knowledge contact lookup (`pir` module)

---

## Troubleshooting

**Connection fails**: The peer may be behind NAT. Ensure STUN works or use
a public IP. Run `./target/release/nullnode dht --find NN-THEIR-ID` to check
DHT lookup.

**DHT lookup fails**: Check bootstrap seeds are reachable. Try running your
own bootstrap node locally: `./target/release/nullnode-bootstrap --port 9001` and point
`NULLNODE_DHT_BOOTSTRAP` to it.

**Encryption fails**: Ensure the recipient's key is trusted. GPG will refuse
to encrypt to untrusted keys. Set trust explicitly.

**Slow PoW**: The proof-of-work takes ~0.5s per DHT write and ~0.1s per
P2P handshake. This is intentional to prevent spam. On a slow machine, it
may take up to 2s.
