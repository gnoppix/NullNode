# NullNode

**Decentralized, post-quantum encrypted messaging -- no phone, no email, no PII.**

NullNode is a privacy-first messenger protocol and client suite. Identity is derived
entirely from a local GPG key pair; the server never sees a real-world identifier.
Messages are encrypted with **ML-KEM (Kyber-768)**, the NIST FIPS-203 post-quantum
standard, via GnuPG 2.5.20.

In general, you could say it is a messenger that secures text messages with post-quantum encryption, sending them directly to your 
friends—similar to a BitTorrent for messaging. 

Newer and faster computers will soon make it possible to decrypt today's messages on "normal" chat programs. Furthermore, with backdoors and decryption methods built into these platforms, mass worldwide surveillance becomes effortless.

With NullNode, that is impossible. There is no central server in between, and your messages aren't just strongly encrypted they are super 
strongly encrypted.

Note: Please consider supporting the project! I simply cannot fund all of the required hosting servers on my own.

---

## Features

- **Zero-knowledge identity** -- 8-character Null ID (`NN-XXXX-XXXX`) is a
  deterministic hash of your GPG fingerprint. No sign-up, no account.
- **Post-quantum encryption** -- every message is encrypted with Kyber-768 +
  AES256 (via `gpg --require-pqc-encryption`).
- **Forward secrecy** -- double ratchet with per-message ephemeral keys.
  Past messages remain unreadable even if the long-term key is compromised.
- **Peer-to-peer messaging** -- direct WebSocket connections when both peers
  are online. Handshake with proof-of-work + signature verification.
- **DHT mailbox** -- encrypted messages stored in a Kademlia-style DHT when
  the recipient is offline. Retrieved on reconnect (polled every 30s).
- **Proof-of-work anti-spam** -- DHT writes require difficulty 16 (~0.5s),
  P2P handshakes require difficulty 12 (~0.1s).
- **NAT traversal** -- STUN + UDP hole punching for clients behind home routers.
- **Federated relays** -- relays can peer with each other for cross-relay
  message delivery with HMAC-authenticated challenge-response.
- **CLI-first** -- full-featured terminal client; ideal for lean environments,
  SSH sessions, and automation.
- **Bot/scanner detection** -- suspicious connections logged to
  `bot_connection.log` in the application directory.

---

## Features coming soon

- A cool desktop UI
- File sharing
- Voice and video calls


## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/gnoppix/NullNode/main/install.sh | bash
```


### Prerequisites

- Gnoppix Linux 26.7
- Python 3.13+
- GnuPG 2.5.20 (verify with `gpg --version` -- must list `Kyber` as a public-key
  algorithm)
- `websockets` library (installed automatically by the launcher)

### 1. Alice creates an identity (terminal 1)

```bash
cd /home/amu/Gnoppix/messenger
source venv/bin/activate

./nullnode.sh init
# -> identity created: NN-P4DM-WZPF

./nullnode.sh id
# -> Null ID:     NN-P4DM-WZPF
# -> fingerprint: F5B0F201378A72EF973A88D170B7096AD5713AA7

./nullnode.sh export > alice_pub.asc
```

### 2. Bob creates an identity (terminal 2)

```bash
cd /home/amu/Gnoppix/messenger
source venv/bin/activate
export NULLNODE_GNUPGHOME=~/.nullnode-bob

./nullnode.sh init
# -> identity created: NN-VJWY-YQMK

./nullnode.sh export > bob_pub.asc
```

### 3. Exchange public keys

```bash
# Alice imports Bob's key
./nullnode.sh import bob_pub.asc --alias NN-VJWY-YQMK

# Bob imports Alice's key
NULLNODE_GNUPGHOME=~/.nullnode-bob ./nullnode.sh import alice_pub.asc --alias NN-P4DM-WZPF
```

**IMPORTANT**: Verify fingerprints out-of-band before trusting! Then set trust:

```bash
# Alice sets trust for Bob
python3 -c "from crypto import set_key_trust; set_key_trust('BOB_FP', 'ultimate')"

# Bob sets trust for Alice
NULLNODE_GNUPGHOME=~/.nullnode-bob python3 -c "from crypto import set_key_trust; set_key_trust('ALICE_FP', 'ultimate')"
```

### 4. Start P2P nodes

```bash
# Alice
./nullnode.sh p2p --port 9001

# Bob (different terminal)
NULLNODE_GNUPGHOME=~/.nullnode-bob ./nullnode.sh p2p --port 9002
```

### 5. Chat

```bash
# Alice sends to Bob
./nullnode.sh send NN-VJWY-YQMK "Hello post-quantum world!" --fingerprint BOB_FP

# Or interactive chat
./nullnode.sh chat NN-VJWY-YQMK --fingerprint BOB_FP
> Hello Bob!
> /quit
```

---

## CLI reference

| Command | Description |
|---|---|
| `init` | Generate a PQC identity (Kyber-768 + brainpoolP384r1) |
| `id` | Show your Null ID and GPG fingerprint |
| `export` | Print your armored PGP public key to stdout |
| `import <file>` | Import a peer's public key from file (or stdin) |
| `import <file> --alias <NID>` | Import and register as a contact |
| `contacts` | List registered contacts (NID -> fingerprint) |
| `p2p --port N` | Start P2P node and listen for messages |
| `send <NID> <msg>` | Send a message to a peer (P2P or DHT mailbox) |
| `send <NID> <msg> --fingerprint <FP>` | Send using explicit fingerprint |
| `chat <NID>` | Interactive P2P chat session |
| `chat <NID> --fingerprint <FP>` | Chat with explicit fingerprint |
| `dht` | DHT diagnostics (find, advertise) |
| `relay` | Start the legacy WebSocket relay server |

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `NULLNODE_RELAY` | `ws://127.0.0.1:8765` | Legacy relay URL (fallback only) |
| `NULLNODE_GNUPGHOME` | `~/.nullnode/gnupg` | GPG home directory |
| `NULLNODE_GPG` | `gpg` | Path to the `gpg` binary |
| `NULLNODE_DHT_BOOTSTRAP` | (3 built-in seeds) | Comma-separated bootstrap DHT seeds |
| `NULLNODE_BOOTSTRAP_CERT` | (empty) | Path to TLS certificate (PEM) -- enables wss:// on bootstrap |
| `NULLNODE_BOOTSTRAP_KEY` | (empty) | Path to TLS private key (PEM) -- enables wss:// on bootstrap |

---

## P2P node

When you run `p2p`, the node:

1. Starts a DHT node (joins the Kademlia network via bootstrap seeds)
2. Starts a P2P WebSocket listener on the specified port
3. Advertises your address in the DHT
4. Polls your DHT mailbox every 30s for offline messages

```bash
./nullnode.sh p2p --port 9001
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

**Running a bootstrap server with TLS:**

```bash
# Get a certificate (Let's Encrypt)
certbot certonly --standalone -d bootstrap-eu.gnoppix.org

# Start with TLS
export NULLNODE_BOOTSTRAP_CERT=/etc/letsencrypt/live/bootstrap-eu.gnoppix.org/fullchain.pem
export NULLNODE_BOOTSTRAP_KEY=/etc/letsencrypt/live/bootstrap-eu.gnoppix.org/privkey.pem
export NULLNODE_BOOTSTRAP_PORT=9001
./nullnode.sh bootstrap
```

Without the cert env vars, the bootstrap server falls back to plain `ws://`
(fully backward compatible).

### Sending a message

The client tries direct P2P first. If the peer is unreachable, it falls back
to storing an encrypted blob in the DHT mailbox:

```bash
./nullnode.sh send NN-VJWY-YQMK "Hello!" --fingerprint BOB_FP
```

### DHT diagnostics

```bash
# Look up a peer's address
./nullnode.sh dht --find NN-VJWY-YQMK

# Advertise your address
./nullnode.sh dht --advertise "wss://your-public-ip:9001"
```

---

## Legacy relay deployment

The relay is a **legacy fallback** for environments where P2P is not possible.
The primary architecture is P2P + DHT.

### Docker

```bash
docker build -t nullnode-relay .
docker run -d \
  --name nullnode-relay \
  --restart unless-stopped \
  -p 8765:8765 \
  nullnode-relay
```

### Native

```bash
python relay.py --host 0.0.0.0 --port 8765 --verbose
```

The relay is stateless -- all sessions and queues are in-memory. For horizontal
scaling, add a shared Redis backend (not yet implemented; see `relay.py`).

### Federation

Relays can peer with each other for cross-relay message delivery:

```bash
# On relay A: peer with relay B
python relay.py --port 8765 --peer wss://relay-b.example.com:8765 --peer-secret SHARED_SECRET
```

---

## Architecture

### End-to-end message flow

```
+--- ALICE'S MACHINE -----------------------------------------------------------+
|                                                                              |
|  +-------------+      1. generate_keypair()                                  |
|  |  gpg keyring |  -->  gpg --quick-gen-key ... pqc ...                     |
|  |  (secret)    |       +-- primary: brainpoolP384r1 [SC]                    |
|  |  + public    |       +-- subkey:  ky768_bp256     [E]                     |
|  +------+------+                                                           |
|         | fingerprint: F5B0F201378A72EF...                                   |
|         |                                                                     |
|         v                                                                     |
|  +--------------+      2. null_id(fingerprint)                               |
|  |  Null ID      |  -->  blake2b(fingerprint, 8) -> base32[:8]               |
|  |  NN-P4DM-WZPF |       +-- "NN-XXXX-XXXX" (8 chars, no PII)               |
|  +--------------+                                                           |
|                                                                              |
|  +--------------+      3. export_pubkey()                                    |
|  |  armored key  |  -->  gpg --armor --export                                |
|  |  (PGP packet) |       +-- sent to peer out-of-band                        |
|  +--------------+                                                           |
|                                                                              |
|  +--------------+      4. DHT lookup("NN-VJWY-YQMK")                       |
|  |  DHT query    |  -->  Kademlia FIND_VALUE -> "wss://bob:9001"            |
|  +--------------+                                                           |
|                                                                              |
|  +--------------+      5. P2P handshake (p2p-hello + PoW)                  |
|  |  WebSocket    |  -->  direct connection to Bob                            |
|  |  handshake    |       +-- both sides solve PoW puzzle                     |
|  +------+-------+       +-- verify signatures                                |
|         |                                                                     |
|         v                                                                     |
|  +--------------+      6. Double ratchet encrypt                            |
|  |  ciphertext   |  -->  fresh ephemeral Kyber encapsulation per message     |
|  |  (armored)    |       +-- AES256 encrypts plaintext                       |
|  +------+-------+       +-- sequence number + timestamp + hash               |
|         |                                                                     |
|         |  base64(ciphertext)                                                 |
|         v                                                                     |
+---------+--------------------------------------------------------------------+
          |
          |  JSON envelope { type: "p2p-message", payload: { seq, ciphertext, msg_hash } }
          |
          v
+--- BOB'S MACHINE ----------------------------------------------------------+
|                                                                            |
|  +-------------+      7. verify hash, decrypt                              |
|  |  gpg keyring |  -->  Kyber-768 decapsulation -> session key               |
|  |  (secret)    |       +-- AES256 decrypt -> plaintext                     |
|  +------+------+       +-- verify sequence number (anti-replay)             |
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
  |  ./nullnode.sh init              |  ./nullnode.sh init
  |  +-- gpg gen brainpoolP384r1    |  +-- gpg gen brainpoolP384r1
  |     + ky768_bp256 subkey        |     + ky768_bp256 subkey
  |                                  |
  |  ./nullnode.sh export > key.asc  |
  |  ------------------------------->|
  |                                  |  ./nullnode.sh import key.asc
  |                                  |  +-- gpg --import
  |                                  |  +-- register_contact(NN-..., FP)
  |                                  |
  |  |                               |  ./nullnode.sh export > key.asc
  |  <-------------------------------|  (verify fingerprint out-of-band!)
  |  ./nullnode.sh import key.asc    |
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
  Ciphertext (Kyber)  present            opaque blob        present
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

**Changes needed for this topology:** Already implemented.

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

**Status:** Implemented in `relay.py`. Kept as fallback for environments
where P2P is not possible.

### 3. Federated relays

```
        +--------------+          inter-relay          +--------------+
        |  Relay Alpha |  <------- WebSocket --------> |  Relay Beta  |
        |  alice.net   |                                |  bob.io      |
        +--+------+----+                                +--+------+----+
      +----+      +----+                              +----+      +----+
   +--+--+    +--+--+                              +--+--+    +--+--+
   | A   |    | B   |                              | C   |    | D   |
   +-----+    +-----+                              +-----+    +-----+
```

Relays peer with each other over a separate inter-relay WebSocket. Each
relay maintains two route tables:

```python
local_sessions:  dict[NullID, WebSocket]     # local clients
remote_routes:   dict[NullID, RelayURL]      # peers on other relays
```

**Status:** Implemented in `relay.py`. Routes gossiped every 60s.
HMAC challenge-response authenticates peer connections.

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

**Status:** Implemented in `p2p.py` + `dht.py`.

### Topology comparison

| Topology | SPOF | Offline delivery | Address discovery | Complexity |
|---|---|---|---|---|
| **P2P + DHT** (default) | No | Yes (DHT mailbox) | DHT | Medium |
| **Legacy relay** | Yes | Yes (queue) | None (same URL) | Low |
| **Federated relays** | No | Yes (per-relay queue) | Gossip or DHT | High |
| **Mesh / DHT** | No | No | DHT | Medium |

---

## Security considerations

- **Key verification** -- NullNode does **not** implement automatic key
  verification. Always verify fingerprints out-of-band (QR scan, in-person,
  PGP signed email) before trusting a peer's key.
- **Relay trust** -- the relay is trusted only for availability, not
  confidentiality. Messages are encrypted before leaving the client.
- **Forward secrecy** -- implemented via double ratchet. Each message uses
  a fresh ephemeral Kyber encapsulation. Past messages remain unreadable
  even if the long-term key is compromised.
- **Metadata** -- the relay sees sender/receiver Null IDs and connection
  timestamps. Route through Tor (`NULLNODE_RELAY=ws://...onion...`) to
  obscure IP metadata.
- **DHT privacy** -- DHT nodes see encrypted blobs and null IDs but
  cannot read message content. The publisher's fingerprint is visible in
  DHT records (needed for signature verification).

---

## License

Prototype -- no license specified. See source files.
