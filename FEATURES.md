# NullNode Features & Setup Guide

## What is NullNode?

NullNode is a peer-to-peer encrypted messenger. There is no central server
that reads your messages. Messages are encrypted with post-quantum Kyber-768
(ML-KEM) and can be delivered either directly (peer-to-peer) or through a
distributed DHT mailbox (like a dead drop).

If both people are online, messages flow directly between them. If the
recipient is offline, messages are stored encrypted in the DHT and retrieved
when they come back online.

---

## Current Features

### Cryptography

- **Post-quantum encryption**: ML-KEM-768 (Kyber) + AES-256 via GPG 2.5.20
- **Forward secrecy**: Double ratchet with per-message ephemeral keys.
  Each message uses a fresh Kyber encapsulation. If your long-term key is
  compromised, past messages remain unreadable and future messages recover
  after the next ratchet step.
- **Anti-replay**: Timestamps (5-minute clock skew tolerance) + sequence
  numbers prevent message replay. Skipped-key tracking with DoS cap (100).
- **Identity binding**: Your Null ID (NN-XXXX-XXXX) is a one-way hash of
  your GPG fingerprint. No one can claim your identity without your key.
- **Explicit trust**: Keys must be manually trusted before use. No automatic
  trust, no trust bypass. `set_key_trust()` only after out-of-band verification.
- **Message signing**: All P2P handshake and DHT write operations are signed
  with the sender's GPG key for authenticity. Signature verification extracts the
  signing key fingerprint from GPG status output and compares it to the expected
  fingerprint using constant-time comparison (prevents key substitution attacks).

### Network

- **Peer-to-peer messaging**: Direct WebSocket connections when both peers
  are online. Handshake with proof-of-work + signature verification.
- **DHT mailbox (store-and-forward)**: Encrypted messages stored in a
  Kademlia-style DHT when the recipient is offline. Retrieved on reconnect
  (polled every 30s).
- **Proof-of-work anti-spam**: Every DHT write requires solving a hash
  puzzle (~0.5s on modern CPU, difficulty 16). P2P handshakes use a
  lighter puzzle (difficulty 12, ~0.1s). Spam is economically infeasible.
- **NAT traversal**: STUN protocol + UDP hole punching for clients behind
  home routers. Multiple STUN servers tried with retries.
- **Bootstrap DHT seeds**: 3 bootstrap nodes help you join the network.
  They never see message content or metadata.
- **Stealth mode**: Set `NULLNODE_STEALTH=true` to return ambiguous responses
  to non-client connections. Port scanners and bots receive "HTTP/1.1 400 Bad
  Request" or empty responses instead of "dht-error" JSON, making fingerprint
  identification harder.
- **Federated relays**: Relays can peer with each other for cross-relay
  message delivery. Route discovery via gossip + who-has queries.
  HMAC challenge-response authenticates peer relay connections.

### Storage

- **Persistent DHT storage**: SQLite-backed message store on each DHT node
  (`~/.nullnode/dht_store.db`, WAL mode).
- **TTL-based expiry**: Address records expire after 2h, messages after 24h.
- **In-memory ratchet state**: Forward secrecy keys live in memory only,
  never written to disk.

### Security hardening

- **DHT address ownership verification**: Address records in the DHT are
  signed by the publisher's GPG key. The signature covers `null_id|address|ttl`,
  proving the publisher owns the private key for that null_id. Prevents DHT
  address spoofing MITM attacks.
- **TOFU pinning**: First address received for a null_id is trusted and pinned
  to disk (`~/.nullnode/pin_cache.json`). Subsequent addresses must match the
  pin -- mismatches are rejected with a warning (possible MITM).
- **Constant-time comparison**: All security-sensitive comparisons use
  `hmac.compare_digest` to prevent timing attacks.
- **Secure temp file handling**: Signature verification uses temp files in
  0700 directories, overwritten with random bytes before deletion.
- **Container runs as non-root**: Docker image uses `USER nullnode`.
- **Rate limiting**: Connection (50/60s) and message (120/60s) rate limits
  per source IP. Global queue cap (10,000). Max 10 sessions per Null ID.
- **Input validation**: All fingerprints, null IDs, and message sizes are
  validated before processing.
- **Timestamp freshness**: DHT and P2P envelopes rejected if timestamp is
  too far from local clock (5-minute window).

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
|  Bootstrap seeds (join only, no message handling):        |
|  wss://bootstrap-eu.gnoppix.org:9001                      |
|  wss://bootstrap-us.gnoppix.org:9001                      |
|  wss://bootstrap-asia.gnoppix.org:9001                    |
|                                                           |
|  Legacy relay (fallback only):                            |
|  ws://127.0.0.1:8765                                      |
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

- Python 3.13+
- GnuPG 2.5.20+ (verify Kyber support: `gpg --version` should list
  `Kyber` under public-key algorithms)
- `websockets` Python library

### Install

```bash
cd /home/amu/Gnoppix/messenger
python3 -m venv venv
source venv/bin/activate
pip install websockets
```

### Create your identity

```bash
source venv/bin/activate
python3 client.py init
```

Output:
```
identity created: NN-P4DM-WZPF
fingerprint: F5B0F201378A72EF973A88D170B7096AD5713AA7
gpg homedir: /home/amu/.nullnode/gnupg
```

Your Null ID is `NN-P4DM-WZPF`. This is what you share with others so they
can find and message you.

### View your identity

```bash
python3 client.py id
```

### Export your public key

```bash
python3 client.py export > mykey.asc
```

Share `mykey.asc` with people so they can import your key and message you.

### Import a peer's public key

```bash
python3 client.py import theirkey.asc --alias NN-THEIR-ID
```

**IMPORTANT**: After importing, verify the fingerprint out-of-band (voice call,
in-person, etc.) before trusting it. Then set trust:

```bash
python3 -c "
from crypto import set_key_trust
set_key_trust('THEIR_FINGERPRINT_HERE', 'ultimate')
"
```

### List contacts

```bash
python3 client.py contacts
```

---

## Running a P2P Node (Client)

### Start listening for messages

```bash
source venv/bin/activate
python3 client.py p2p --port 9001
```

This starts a P2P node that:
- Listens for incoming connections on port 9001
- Joins the DHT network via bootstrap seeds
- Advertises your address in the DHT
- Polls your DHT mailbox every 30s

### Send a message

```bash
python3 client.py send NN-THEIR-ID "Hello, this is a secret message" --fingerprint THEIR_FP
```

### Interactive chat

```bash
python3 client.py chat NN-THEIR-ID --fingerprint THEIR_FP
```

This opens an interactive session. Type messages, press Enter to send, type
`/quit` to exit.

### DHT diagnostics

```bash
# Look up a peer's address
python3 client.py dht --find NN-THEIR-ID

# Advertise your address
python3 client.py dht --advertise "wss://your-public-ip:9001"
```

---

## Running a Bootstrap DHT Seed (Server)

A bootstrap node is NOT a message relay. It only helps clients join the DHT
network. It never sees message content.

### Option 1: Direct

```bash
source venv/bin/activate
python3 client.py p2p --port 9001
```

This starts both a P2P listener and a DHT node. The node will be reachable
on port 9001. You can also run just a DHT node:

```bash
python3 client.py dht --port 6881
```

### Option 2: Docker

```bash
docker build -t nullnode .
docker run -p 9001:9001 -p 6881:6881 nullnode p2p --port 9001
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

## Running a Legacy Relay (Fallback)

The relay is now a **legacy fallback** for environments where P2P is not
possible. The primary architecture is P2P + DHT.

```bash
source venv/bin/activate
python relay.py --port 8765
```

Or via Docker:

```bash
docker build -t nullnode-relay .
docker run -p 8765:8765 nullnode-relay
```

Clients can use the relay by setting `NULLNODE_RELAY` (the P2P code ignores
this variable -- it's only for the legacy relay path).

---

## Quick Start: Two Users

### Terminal 1: Alice

```bash
cd /home/amu/Gnoppix/messenger
source venv/bin/activate

# Create identity
python3 client.py init
# -> identity created: NN-ALICE-ID
# -> fingerprint: AAAA...

# Export public key
python3 client.py export > alice.asc

# Start P2P node
python3 client.py p2p --port 9001
```

### Terminal 2: Bob

```bash
cd /home/amu/Gnoppix/messenger
source venv/bin/activate
export NULLNODE_GNUPGHOME=~/.nullnode-bob

# Create identity
python3 client.py init
# -> identity created: NN-BOB-ID
# -> fingerprint: BBBB...

# Export public key
python3 client.py export > bob.asc

# Import Alice's key
python3 client.py import alice.asc --alias NN-ALICE-ID

# Set trust (after verifying fingerprint out-of-band!)
python3 -c "from crypto import set_key_trust; set_key_trust('AAAA...', 'ultimate')"

# Start P2P node
python3 client.py p2p --port 9002
```

### Terminal 1: Alice sends to Bob

```bash
python3 client.py send NN-BOB-ID "Hello Bob!" --fingerprint BBBB...
```

Or interactive chat:

```bash
python3 client.py chat NN-BOB-ID --fingerprint BBBB...
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NULLNODE_RELAY` | `ws://127.0.0.1:8765` | Legacy relay URL (fallback only) |
| `NULLNODE_GNUPGHOME` | `~/.nullnode/gnupg` | GPG home directory |
| `NULLNODE_GPG` | `gpg` | Path to GPG binary |
| `NULLNODE_DHT_BOOTSTRAP` | (3 built-in seeds) | Comma-separated bootstrap DHT seeds |

---

## Security Checklist

Before relying on NullNode for sensitive communication:

- [ ] Verify your GPG key has Kyber support: `gpg --version | grep -i kyber`
- [ ] Verify peer fingerprints out-of-band (voice, in-person, etc.)
- [ ] Set key trust to `ultimate` only after verification
- [ ] Run your own bootstrap seed if you don't trust the public ones
- [ ] Use a firewall to limit exposure of DHT port (6881) if needed
- [ ] Keep your GPG home directory secure (`chmod 700 ~/.nullnode/gnupg`)
- [ ] Never share your secret key -- only export public keys

---

## Troubleshooting

**Connection fails**: The peer may be behind NAT. Ensure STUN works or use
a public IP. Run `python3 -c "import asyncio; from nat import get_public_endpoint; print(asyncio.run(get_public_endpoint()))"` to check STUN.

**DHT lookup fails**: Check bootstrap seeds are reachable. Try running your
own bootstrap node locally: `python3 client.py dht --port 6881` and point
`NULLNODE_DHT_BOOTSTRAP` to it.

**Encryption fails**: Ensure the recipient's key is trusted. GPG will refuse
to encrypt to untrusted keys. Set trust explicitly.

**Slow PoW**: The proof-of-work takes ~0.5s per DHT write and ~0.1s per
P2P handshake. This is intentional to prevent spam. On a slow machine, it
may take up to 2s.
