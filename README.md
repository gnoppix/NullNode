# NullNode

**Decentralized, encrypted messaging -- no phone, no email, no PII.**

NullNode is a privacy-first messenger protocol and client suite. Identity is
derived entirely from a local key pair; the server never sees a
real-world identifier. Messages are encrypted with **Kyber-768 KEM** (ML-KEM,
NIST Level 3, FIPS 203 compliant) — there is NO classical fallback. All user
messages use a "KEM-then-AEAD" construction: a fresh ephemeral Kyber-768
keypair per message encapsulates a shared secret, which encrypts the actual
message payload via AES-256-GCM (forward secrecy + replay protection).

In general, you could say it is a messenger that secures text messages with
strong encryption, sending them directly to your friends -- similar to a
BitTorrent for messaging.

Newer and faster computers will soon make it possible to decrypt today's
messages on "normal" chat programs. Furthermore, with backdoors and decryption
methods built into these platforms, mass worldwide surveillance becomes
effortless.

With NullNode, that is impossible. There is no central server in between, and
your messages aren't just strongly encrypted they are super strongly encrypted.

Note: Please consider supporting the project! I simply cannot fund all of the
required hosting servers on my own.

---

## Features

- **Zero-knowledge identity** -- 8-character Null ID (`NN-XXXX-XXXX`) is a
  deterministic hash of your Ed25519 public key. No sign-up, no account.
- **Kyber-768 KEM (ML-KEM)** -- ALL user messages use Kyber-768 post-quantum
  key encapsulation. There is NO classical fallback. "KEM-then-AEAD" construction:
  fresh ephemeral Kyber-768 keypair per message, shared secret encrypts the
  payload via AES-256-GCM. Wire format: ephemeral_pk || kyber_ct || nonce || aes_ct.
- **Forward secrecy** -- double ratchet with per-message ephemeral Kyber keys
  + HKDF-SHA256 chain key evolution. Sessions persist across restarts.
- **Peer-to-peer messaging** -- direct WebSocket connections when both peers
  are online. Handshake with proof-of-work + signature verification.
- **Client commands** -- `send` (DHT lookup + P2P delivery), `read` (relay
  mailbox fetch + decrypt), `listen` (WebSocket listener for incoming connections).
- **DHT mailbox** -- encrypted messages stored in a centralized DHT when
  the recipient is offline. Retrieved on reconnect (polled every 30s).
- **SQLite message persistence** -- local message store at `~/.nullnode/messages.db`
  for message history and offline retrieval.
- **Safety number verification (G6)** -- deterministic safety number for
  out-of-band key verification. Detects man-in-the-middle attacks.
- **Proof-of-work anti-spam** -- DHT writes require Argon2id memory-hard
  puzzle (~0.5s, 16MB memory). GPU/ASIC-resistant: botnet throughput reduced
  by ~500,000x vs SHA-256 hashcash.
- **NAT traversal** -- STUN + UDP hole punching for clients behind home routers.
- **Single-relay model** -- one relay per deployment; federation is a future
  enhancement (documented as intentional G7).
- **CLI-first** -- full-featured terminal client; ideal for lean environments,
  SSH sessions, and automation.
- **Bot/scanner detection** -- suspicious connections logged to
  `bot_connection.log` in the application directory.
- **Tor support (optional)** -- route all traffic through Tor for IP-level
  privacy via hidden service.
- **I2P transport** -- not implemented (documented as intentional G8).
  Tor-first approach; I2P support planned as future enhancement.
- **Key persistence** -- Kyber-768 keypairs and ratchet sessions persist to
  disk with 0o600 permissions. DHT address stays stable across restarts.

---

## Features coming soon

- A cool desktop UI
- File sharing
- Voice and video calls

---

## Quick start

### Prerequisites

- Rust 1.75+
- Cargo
- Sequoia OpenPGP 2.3.0 (in-process OpenPGP, no system gpg binary needed)
- Tor daemon (optional, for IP masking)

### 1. Build from source

```bash
cd rust
make all
```

### 2. Alice creates an identity (terminal 1)

```bash
cd rust
./target/release/nullnode init
# -> identity created: NN-P4DM-WZPF

./target/release/nullnode id
# -> Null ID:     NN-P4DM-WZPF
# -> fingerprint: F5B0F201378A72EF973A88D170B7096AD5713AA7

./target/release/nullnode export > alice_pub.asc
```

### 3. Bob creates an identity (terminal 2)

```bash
cd rust
./target/release/nullnode init
# -> identity created: NN-VJWY-YQMK

./target/release/nullnode export > bob_pub.asc
```

### 4. Exchange public keys

```bash
# Alice imports Bob's key
./target/release/nullnode import bob_pub.asc --alias NN-VJWY-YQMK

# Bob imports Alice's key
./target/release/nullnode import alice_pub.asc --alias NN-P4DM-WZPF
```

**IMPORTANT**: Verify fingerprints out-of-band before trusting!

### 5. Start P2P nodes

```bash
# Alice
./target/release/nullnode p2p --port 9001

# Bob (different terminal)
./target/release/nullnode p2p --port 9002
```

### 6. Chat

```bash
# Alice sends to Bob
./target/release/nullnode send NN-VJWY-YQMK "Hello post-quantum world!" --fingerprint BOB_FP

# Or interactive chat
./target/release/nullnode chat NN-VJWY-YQMK --fingerprint BOB_FP
> Hello Bob!
> /quit
```

---

## CLI reference

| Command | Description |
|---|---|
| `init` | Generate an OpenPGP identity (Sequoia) and Null ID |
| `id` | Show your Null ID and OpenPGP fingerprint |
| `export` | Print your armored OpenPGP public key to stdout |
| `import <file>` | Import a peer's public key from file (or stdin) |
| `import <file> --alias <NID>` | Import and register as a contact |
| `contacts` | List registered contacts (NID -> fingerprint) |
| `add-contact <NID> --fingerprint <FP>` | Add a contact with verified fingerprint |
| `send <NID> <msg>` | Send a message (DHT lookup + P2P + fallback to DHT mailbox) |
| `send <NID> <msg> --fingerprint <FP>` | Send using explicit fingerprint |
| `read` | Read messages from relay mailbox + local store |
| `listen` | Start P2P WebSocket listener for incoming connections |
| `chat <NID>` | Interactive P2P chat session |
| `chat <NID> --fingerprint <FP>` | Chat with explicit fingerprint |
| `verify <NID>` | Show safety number for contact verification (G6) |
| `safety-number <NID>` | Show your safety number for a contact (G6) |
| `status` | Show DHT status and configuration |
| `dht` | DHT diagnostics (find, advertise) |
| `relay` | Start the legacy WebSocket relay server |

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `NULLNODE_RELAY` | `ws://127.0.0.1:8765` | Legacy relay URL (fallback only) |
| `NULLNODE_DHT_BOOTSTRAP` | (3 built-in seeds) | Comma-separated bootstrap DHT seeds |
| `NULLNODE_USE_TOR` | `false` | Enable Tor transport (IP masking) |
| `NULLNODE_TOR_SOCKS` | `socks5://127.0.0.1:9050` | Tor SOCKS5 proxy address |
| `NULLNODE_ONION_ADDRESS` | (empty) | Pre-configured .onion address (required for Tor inbound) |
| `NULLNODE_ONION_PORT` | `9001` | Port for Tor hidden service |

---

## P2P node

When you run `p2p`, the node:

1. Starts a DHT node (joins the Kademlia network via bootstrap seeds)
2. Starts a P2P WebSocket listener on the specified port
3. Advertises your address in the DHT
4. Polls your DHT mailbox every 30s for offline messages

```bash
./target/release/nullnode p2p --port 9001
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

### Sending a message

The client tries direct P2P first. If the peer is unreachable, it falls back
to storing an encrypted blob in the DHT mailbox:

```bash
./target/release/nullnode send NN-VJWY-YQMK "Hello!" --fingerprint BOB_FP
```

### DHT diagnostics

```bash
# Look up a peer's address
./target/release/nullnode dht --find NN-VJWY-YQMK

# Advertise your address
./target/release/nullnode dht --advertise "wss://your-public-ip:9001"
```

---

## Relay deployment (Federated Multi-Relay)

The relay supports **multi-relay federation** with gossip-based message forwarding.
Multiple relays can connect to each other to form a federated network.

### Native

```bash
# Start a relay with peer connections
./target/release/nullnode-relay --host 0.0.0.0 --port 8765 \
  --peer ws://relay-b.example.com:8765 \
  --peer ws://relay-c.example.com:8765 \
  --secret-file /path/to/shared_secret.txt

# Or read peers from a file (one URL per line, # comments allowed)
./target/release/nullnode-relay --host 0.0.0.0 --port 8765 \
  --peer-file /path/to/peers.txt
```

### Federation protocol

- **Peer connections**: Relays connect to each other via WebSocket (`--peer`)
- **Route advertisement**: Periodic gossip (every 60s) advertises which Null IDs
  are served by each relay
- **Message forwarding**: When a relay receives a message for a Null ID on a
  peer relay, it forwards via `relay-forward` (max 5 hops, loop detection)
- **Authentication**: HMAC-SHA256 challenge-response between peers using a
  shared secret

### CLI arguments

| Argument | Description |
|---|---|
| `--host` | Listen address (default: 0.0.0.0) |
| `--port` | Listen port (default: 8765) |
| `--peer` | Peer relay URL (repeatable) |
| `--peer-file` | Read peer URLs from a file |
| `--secret` | Shared peer secret (prefer --secret-file) |
| `--secret-file` | Read shared secret from file (0o600) |
| `--url` | Our advertised URL (auto-detected if omitted) |
| `--cert-dir` | Directory containing own cert (default: ~/.nullnode/certs) |
| `--tls-cert` | TLS certificate (PEM) for wss:// |
| `--tls-key` | TLS private key (PEM) for wss:// |

---

## Architecture

### End-to-end message flow

```
+--- ALICE'S MACHINE -----------------------------------------------------------+
|                                                                              |
|  +-------------+      1. init (Sequoia OpenPGP keypair)                       |
|  |  cert store  |  -->  Cv25519 + ky768_bp256                                    |
|  |  (secret)    |                                                           |
|  |  + public    |       +-- Null ID derived from fingerprint               |
|  +------+------+                                                           |
|         | fingerprint: F5B0F201378A72EF...                                   |
|         |                                                                     |
|         v                                                                     |
|  +--------------+      2. DHT lookup("NN-VJWY-YQMK")                       |
|  |  DHT query    |  -->  Kademlia FIND_VALUE -> "wss://bob:9001"            |
|  +--------------+                                                           |
|                                                                              |
|  +--------------+      3. P2P handshake (p2p-hello + PoW)                  |
|  |  WebSocket    |  -->  direct connection to Bob                            |
|  |  handshake    |       +-- both sides solve PoW puzzle                     |
|  +------+-------+       +-- verify signatures                                |
|         |                                                                     |
|         v                                                                     |
|  +--------------+      4. Double ratchet encrypt                            |
|  |  ciphertext   |  -->  fresh ephemeral key per message                     |
|  |  (AES-256)    |       +-- sequence number + timestamp + hash               |
|  +------+-------+                                                           |
|         |                                                                     |
|         |  JSON envelope { type: "p2p-message", payload: { seq, ciphertext, msg_hash } } |
|         v                                                                     |
+---------+--------------------------------------------------------------------+
          |
          v
+--- BOB'S MACHINE ----------------------------------------------------------+
|                                                                            |
|  +-------------+      5. verify hash, decrypt                              |
|  |  gpg keyring |  -->  AES-256-GCM decrypt -> plaintext                     |
|  |  (secret)    |       +-- verify sequence number (anti-replay)             |
|  +------+------+                                                           |
|         |                                                                     |
|         v                                                                     |
|  +--------------+                                                            |
|  |  plaintext    |                                                           |
|  |  "Hello Bob!" |                                                           |
|  +--------------+                                                            |
|                                                                            |
+----------------------------------------------------------------------------+
```

### Identity and key exchange

```
ALICE                               BOB
  |                                  |
  |  ./nullnode init                 |  ./nullnode init
  |  +-- GPG gen keypair             |  +-- GPG gen keypair
  |                                  |
  |  ./nullnode export > key.asc     |
  |  ------------------------------->|
  |                                  |  ./nullnode import key.asc
  |                                  |  +-- gpg --import
  |                                  |  +-- register_contact(NN-..., FP)
  |                                  |
  |  |                               |  ./nullnode export > key.asc
  |  <-------------------------------|  (verify fingerprint out-of-band!)
  |  ./nullnode import key.asc       |
  |  +-- gpg --import                |
  |  +-- register_contact(NN-..., FP)|
  |  +-- set_key_trust(FP, ultimate) |
  |                                  |
  |  Now each side has the other's   |
  |  public key, verified fingerprint|
  |  and explicit trust.             |
```

### Wire protocol detail (P2P)

```
ALICE (initiator)                    BOB (responder)
  |                                        |
  |  p2p-hello                             |
  |  { public_key: base64(FP),             |
  |    nonce: N, pow_bits: 12 }           |
  |  sig: base64(gpg_sig)                  |
  | -------------------------------------->|
  |                                        |
  |  p2p-hello-ack                         |
  |  { public_key: base64(FP),             |
  |    nonce: M, pow_bits: 12 }           |
  |  sig: base64(gpg_sig)                  |
  | <--------------------------------------|
  |                                        |
  |  p2p-message                           |
  |  { seq: 0, ciphertext: base64(ct),     |
  |    msg_hash: sha256_hex }              |
  | -------------------------------------->|
  |                                        |
  |  p2p-ack                               |
  |  { seq: 0, msg_hash: sha256_hex }     |
  | <--------------------------------------|
```

### Wire protocol detail (DHT mailbox)

```
ALICE                                   DHT NETWORK
  |                                        |
  |  1. Encrypt message with Bob's key     |
  |  2. Sign with Alice's key              |
  |                                        |
  |  dht-put                               |
  |  { key: "NN-BOB-ID",                   |
  |    value: base64(encrypted_blob),      |
  |    salt: hex, seq: 1,                  |
  |    ttl: 86400,                         |
  |    nonce: pow_solution,                 |
  |    publisher_fp: "ALICE_FP" }          |
  |  sig: base64(gpg_sig)                  |
  | -------------------------------------->|
  |                                        |
  |  (DHT stores encrypted blob)           |
  |                                        |
  |                                        |
BOB                                     DHT NETWORK
  |                                        |
  |  dht-get                               |
  |  { key: "NN-BOB-ID" }                  |
  | -------------------------------------->|
  |                                        |
  |  dht-found                             |
  |  { key: "NN-BOB-ID",                   |
  |    value: base64(encrypted_blob),      |
  |    salt: hex, seq: 1 }                |
  | <--------------------------------------|
  |                                        |
  |  3. Verify signature (Alice's FP)      |
  |  4. Decrypt with Bob's secret key      |
```

### Key material flow (what each layer sees)

```
                      ALICE              P2P/RELAY           BOB
                      -----              ---------           ---
  Null ID             NN-ALICE           NN-ALICE            NN-ALICE
  GPG fingerprint     F5B0F201...        -- (never sent)     F5B0F201...
  Secret key          present            --                  --
  Public key          present            --                  present
  Plaintext           "Hello"            --                  "Hello"
  Ciphertext (AES)    present            opaque blob        present
  Session key (AES)   derived            --                  derived
  IP address          present            present             present
  Message timestamp   present            present             present
```

---

## Network topologies

### 1. P2P + DHT (current default)

```
  +----------+                        +----------+
  |  Alice   |  WebSocket (direct)   |   Bob    |
  |  :9001   |<--------------------->|  :9002   |
  +----+-----+                        +----+-----+
       |                                   |
       |  DHT (store-and-forward)          |
       |  +-----------+                    |
       +->| DHT Node  |<------------------+
          | :6881     |
          +-----------+
```

Each client runs a P2P node + DHT node. Messages flow directly when both
peers are online. Offline messages are stored in the DHT. No relay needed.

### 2. Legacy relay (fallback)

```
     +----------+
     |  Relay   |
     |  :8765   |
     +----+-----+
     +----+-----+
     |    |     |
  +--+-+ +-+-+ +-+-+
  | A  | | B | | C |
  +----+ +---+ +---+
```

All clients register with one relay. The relay forwards messages to the
right WebSocket. Offline messages are queued (max 100, TTL 300s).

**Status:** Implemented as `nullnode-relay`. Kept as fallback for environments
where P2P is not possible.

### 3. Federated relays (multi-relay)

```
        +--------------+          inter-relay          +--------------+
        |  Relay Alpha |  <------- WebSocket --------> |  Relay Beta  |
        |  relay-alpha |   route-adv + relay-forward   |  relay-beta  |
        +--+------+----+                                +--+------+----+
      +----+      +----+                              +----+      +----+
   +--+--+    +--+--+                              +--+--+    +--+--+
   | A   |    | B   |                              | C   |    | D   |
   +-----+    +-----+                              +-----+    +-----+
```

Relays peer with each other over a separate inter-relay WebSocket. Each
relay maintains two route tables:

```rust
local_sessions:  HashMap<NullID, WebSocket>     // local clients
remote_routes:   HashMap<NullID, RelayURL>      // peers on other relays
```

**Status:** Implemented. Use `--peer` to connect relays. Gossip-based route
advertisement every 60s. Messages forwarded via `relay-forward` (max 5 hops,
loop detection via HMAC-SHA256 authenticated peer connections.

### 4. Mesh (DHT only, no relays)

```
  +------+       +------+
  |  A   |<----->|  B   |
  +--+---+       +--+---+
     |              |
  +--+---+       +--+---+
  |  C   |<----->|  D   |
  +------+       +------+
```

Every node runs a DHT client (Kademlia). To send a message: look up
recipient in DHT, connect directly, handshake, exchange messages.

**Status:** Implemented in `nullnode-p2p` + `nullnode-dht-core`.

### Topology comparison

| Topology | SPOF | Offline delivery | Address discovery | Complexity |
|---|---|---|---|---|
| **P2P + DHT** (default) | No | Yes (DHT mailbox) | DHT | Medium |
|| **Legacy relay** | Yes | Yes (queue) | None (same URL) | Low |
|| **Federated relays** | No | Yes (per-relay queue) | Gossip | High |
|| **Mesh / DHT** | No | No | DHT | Medium |

---

## Security considerations

- **Key verification** -- NullNode provides safety number verification (G6)
  for out-of-band key verification. Always compare safety numbers with your
  contact (in-person, voice call, PGP signed email) before trusting a peer's
  key. A safety number mismatch indicates a possible man-in-the-middle attack.
- **Relay trust** -- the relay is trusted only for availability, not
  confidentiality. Messages are encrypted before leaving the client.
- **Forward secrecy** -- implemented via double ratchet. Each message uses
  a fresh ephemeral key derivation. Past messages remain unreadable
  even if the long-term key is compromised. Sessions persist across restarts.
- **Metadata** -- the relay sees sender/receiver Null IDs and connection
  timestamps. Route through Tor to obscure IP metadata.
- **DHT privacy** -- DHT nodes see encrypted blobs and null IDs but
  cannot read message content. The publisher's fingerprint is visible in
  DHT records (needed for signature verification).
- **Key persistence** -- All keys and sessions are stored with 0o600 permissions
  (owner-only read). Kyber-768 keypairs persist so your DHT address stays
  stable across restarts.

---

## License

Business Source License (BSL / BUSL).
You can use the code for free if your company or organisation doesn't have more than 2 people.
