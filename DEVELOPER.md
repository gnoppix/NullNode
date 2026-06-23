# NullNode developer guide

This document describes the internal architecture, module contracts, and
extension points for the NullNode messenger.

---

## Project layout

```
messenger/
├── crypto.py         # GPG wrapper, key management, encrypt/decrypt, double ratchet
├── protocol.py       # JSON envelope dataclass, message types, proof-of-work
├── relay.py          # WebSocket relay (in-memory sessions + queue, federation)
├── client.py         # CLI entry point and all sub-commands
├── p2p.py            # P2P node: direct connections, DHT mailbox, handshake
├── dht.py            # Kademlia-style DHT node with SQLite storage
├── nat.py            # STUN client + UDP hole punching for NAT traversal
├── ratelimit.py      # Sliding-window rate limiter (per-key)
├── nullnode.sh       # Shell launcher (auto-creates venv, dispatches)
├── Dockerfile        # Multi-arch relay/P2P container
├── requirements.txt  # Python dependencies (websockets only)
├── README.md         # User-facing documentation
└── DEVELOPER.md      # This file
```

---

## Module contracts

### `crypto.py` — cryptographic layer

This module wraps GnuPG 2.5.20 subprocess calls. It never imports `pynacl`
or any pure-Python crypto library; all cryptographic operations are delegated
to the system `gpg` binary.

**Key abstraction:**

```python
# All operations use a GPG homedir set via:
crypto.GPG_HOME = "~/.nullnode/gnupg"          # default
crypto.GPG_HOME = os.environ["NULLNODE_GNUPGHOME"]  # override
```

| Function | Returns | Notes |
|---|---|---|
| `generate_keypair()` | `str` (fingerprint) | Creates brainpoolP384r1 + ky768_bp256 key, no passphrase |
| `null_id(fingerprint)` | `str` (`NN-XXXX-XXXX`) | blake2b -> base32 -> 8-char Null ID |
| `validate_null_id(nid)` | `bool` | Syntax check only |
| `validate_null_id_strict(nid, fp)` | `bool` | Verify null_id matches fingerprint hash |
| `validate_fingerprint(fp)` | `bool` | 32- or 40-char hex check |
| `encrypt(plaintext, recipient_fp)` | `str` (armored ciphertext) | `--require-pqc-encryption` |
| `decrypt(armored)` | `str` (plaintext) | Auto-selects secret key from GPG_HOME |
| `export_pubkey()` | `str` (armored) | Full PGP public key packet |
| `import_pubkey(armored)` | `str` (fingerprint) | Imports into GPG_HOME, returns fingerprint |
| `get_fingerprint_from_armored(armored)` | `str \| None` | Read-only inspection |
| `sign_data(data, fingerprint)` | `str` (base64 sig) | Detached GPG signature |
| `verify_signature(data, b64_sig, fp)` | `bool` | Verify detached signature |
| `set_key_trust(fingerprint, level)` | `None` | Explicit trust setting |
| `register_contact(nid, fingerprint)` | `None` | Writes to `~/.nullnode/contacts.json` |
| `resolve_contact(nid)` | `str \| None` | Looks up fingerprint for a Null ID |
| `list_contacts()` | `dict[str, str]` | All registered contacts |
| `own_identity()` | `(nid, fingerprint)` | Current user's identity tuple |

**Double ratchet (forward secrecy):**

| Class | Notes |
|---|---|
| `DoubleRatchetSession(peer_fp, peer_nid, our_fp, is_initiator)` | Per-peer ratchet; in-memory only |
| `.encrypt_message(plaintext)` | Returns `(ciphertext_armored, seq, msg_hash)` |
| `.decrypt_message(ct, claimed_seq, claimed_ts)` | Returns plaintext; enforces anti-replay |

**Design rules:**

1. `_gpg()` always passes `--batch --with-colons` and captures stdout/stderr.
   Never interactive. No `--trust-model always`.
2. `encrypt()` and `decrypt()` raise `RuntimeError` on failure — the calling
   CLI handler is responsible for printing the error.
3. The contacts JSON file is the only state `crypto.py` manages outside the
   GPG keyring. It maps Null ID -> GPG fingerprint.
4. All security-sensitive comparisons use `hmac.compare_digest`.
5. Secure temp files are overwritten with random bytes before deletion.

---

### `protocol.py` — wire format and proof-of-wire

The protocol is JSON over WebSocket. Every message is an `Envelope`:

```python
@dataclass
class Envelope:
    type: MessageType
    payload: dict
    msg_id: str     # hex string, 16 chars (uuid4)
    ts: float      # unix timestamp
    sig: str = ""   # base64-encoded detached GPG signature
```

**Message types (current):**

| Type | Direction | Purpose |
|---|---|---|
| **DHT store-and-forward** | | |
| `dht-put` | node -> DHT | Store encrypted blob with PoW |
| `dht-get` | node -> DHT | Retrieve blob by key |
| `dht-found` | DHT -> node | Blob found response |
|| `dht-error` | DHT -> node | Operation failed |
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
| `online` / `offline` | client -> relay | Presence (stub) |

**Proof-of-work:**

```python
DHT_POW_DIFFICULTY = 16   # ~0.5s on modern CPU, ~65k attempts
P2P_POW_DIFFICULTY = 12   # ~0.1s on modern CPU

pow_solve(data, difficulty) -> int   # find valid nonce
pow_check(data, nonce, difficulty) -> bool  # verify
```

**Adding a new message type:**

1. Add the literal string to `MessageType`.
2. Add a `@classmethod` factory to the `Envelope` class.
3. Handle the new type in the appropriate handler (`relay.Relay._handle_envelope`
   for relay messages, `dht.DHTNode._handle_connection` for DHT, `p2p.P2PNode._handle_connection` for P2P).

---

### `relay.py` — WebSocket relay (legacy fallback)

The `Relay` class maintains in-memory structures:

```python
self.sessions: dict[str, set[WebSocket]]       # Null ID -> active connections
self.message_queue: dict[str, list[(ts, Env)]]  # Offline -> queued messages
self.remote_routes: dict[str, (url, ts)]     # Federated relay routes
self.peer_relays: dict[str, WebSocket]        # Authenticated peer relay connections
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

**Federation:**

Relays authenticate peer connections via HMAC challenge-response (`peer_secret`).
Routes are gossiped every 60s. Cross-relay messages use `relay-forward`
envelopes. Route discovery uses `who-has` / `route-found` queries.

**Message flow (legacy relay):**

```
register:
  1. Verify signature + null_id matches fingerprint
  2. Add ws to sessions[null_id]
  3. Drain message_queue[null_id] (discard expired)
  4. Send "registered"

send:
  1. Build "recv" envelope from "send" payload
  2. If recipient in local sessions -> forward, send "ack"
  3. If recipient in remote_routes -> relay-forward to peer relay
  4. If unknown -> queue message (max 100, TTL 300s), send "ack"

relay-forward:
  1. Accept only from authenticated peer relays
  2. Deliver locally or queue for offline recipient
```

**Extending the relay:**

- To add persistence, replace `message_queue` with a Redis or SQLite backend.
- To add clustering, use a shared Redis for `sessions` across relay instances.

---

### `p2p.py` — P2P node

The `P2PNode` class combines DHT participation with direct peer connections.

```python
class P2PNode:
    # Core
    nid: str
    fingerprint: str
    p2p_port: int = 9001

    # Subsystems
    _dht: DHTNode | None       # DHT participation
    _server: asyncio.Server    # Incoming P2P WebSocket server

    # Peer state
    _peers: dict[str, PeerConnection]  # Active peer connections
    _sessions: dict[str, DoubleRatchetSession]  # Per-peer ratchet
```

**`PeerConnection`:** Wraps a WebSocket + `DoubleRatchetSession`.
- `send(plaintext)` -> encrypts via ratchet, sends `p2p-message`, returns `(seq, msg_hash)`
- `receive()` -> receives envelope, decrypts, verifies hash, sends `p2p-ack`

**Message flow (P2P send):**
1. If peer already connected -> send directly via `PeerConnection.send()`
2. Look up peer address in DHT -> validate signature + TOFU pin
3. Connect WebSocket (rejected if TOFU pin mismatch)
4. Perform handshake: `p2p-hello` (with PoW) -> `p2p-hello-ack`
5. Initialize `DoubleRatchetSession`
6. If peer offline -> fall back to DHT mailbox (`_store_in_mailbox`)

**DHT mailbox:**
- Messages encrypted with recipient's public key before storage
- Signed by sender for authenticity
- Recipient polls mailbox every 30s (`MAILBOX_POLL_INTERVAL`)
- Sequence numbers prevent replay

**Handshake:**
- Both sides solve a PoW puzzle (`P2P_POW_DIFFICULTY = 12`)
- Public keys exchanged as base64-encoded fingerprints
- Both sides sign the `p2p-hello` / `p2p-hello-ack` envelopes

---

### `dht.py` — Kademlia DHT node

The `DHTNode` class implements a Kademlia-style DHT with persistent storage.

```python
class DHTNode:
    node_id: int           # 160-bit, derived from Null ID via SHA-256
    store: DHTStore        # SQLite-backed persistent storage
    routing_table: dict[int, list[dict]]  # XOR-distance buckets
```

**`DHTStore`:** SQLite database (`~/.nullnode/dht_store.db`) with:
- `kv_store` table: key, value, salt, seq, publisher_fp, stored_at, expires_at, sig
- WAL mode, foreign keys
- Automatic expiry via `DELETE WHERE expires_at <= now`

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

**DHT operations:**
- `store_mailbox(recipient_nid, blob, fp, seq)` -> encrypts, signs, stores with PoW
- `get_mailbox(my_nid)` -> polls local store + queries DHT network
- `publish_addr_record(nid, fp, addr)` -> publishes signed address record (proves ownership)
- `lookup(target_nid)` -> iterative FIND_VALUE query; validates address signature + TOFU pin

**Address ownership verification (dht-addr-record):**
```
Publisher signs: null_id|address|ttl
Signature verified against publisher's GPG fingerprint
null_id must equal compute_null_id(publisher_fp)  (proves key ownership)
Stored in DHT with salt prefix "addr:" to distinguish from mailbox data
Returned on lookup() with full signature + publisher_fp metadata
```

**TOFU pinning:**
- First address received for a null_id is trusted and pinned to disk
- Subsequent addresses for the same null_id must match the pin
- Pin mismatch logs a warning and rejects the address (possible MITM)
- Pin cache stored at `~/.nullnode/pin_cache.json`
- `pin_get(null_id)` -> look up pinned address
- `pin_update(null_id, address, fp)` -> update/create pin
- `pin_verify_address(null_id, address)` -> check address against pin

**Security:**
- Every `dht-put` requires valid PoW (difficulty 16)
- Publisher must sign `key|value|salt|seq|nonce`
- Key must equal publisher's null_id (prevents unauthorized storage)
- `dht-addr-record` requires signature over `null_id|address|ttl`
- Anti-replay via nonce tracking
- TOFU pinning prevents DHT address spoofing MITM

**Bootstrap server TLS:**
- Bootstrap servers speak TLS directly on their listen port (no reverse proxy)
- `DHTNode.__init__()` accepts `ssl_certfile` and `ssl_keyfile` params
- `DHTNode.start()` creates `ssl.SSLContext` when both are provided
- `bootstrap_server.py` reads `NULLNODE_BOOTSTRAP_CERT` and `NULLNODE_BOOTSTRAP_KEY` env vars
- Without cert env vars, falls back to plain `ws://` (backward compatible)

**Bootstrap server identity verification (client-side):**
- `verify_bootstrap_cert()` performs raw SSL handshake to extract peer cert fingerprint + validity dates
- `bootstrap_pin_check()` -- TOFU with cert validity window for rotation detection
  - Accepts rotation if cert is currently valid AND was issued within 90 days (Let's Encrypt cycle)
  - Accepts rotation if pin is < 90 days old (short offline period)
  - Rejects if cert is expired, issued > 90 days ago, or pin is > 90 days old
- Domain trust check: cert SAN/CN must match `*.gnoppix.org` or `*.gnoppix.com`
- CA trust check: cert issuer must be Let's Encrypt / ISRG
- Pin cache at `~/.nullnode/bootstrap_pin_cache.json`
- Prevents rogue bootstrap servers from poisoning DHT or redirecting messages

**Bot/scanner detection:**
- `bot_connection.log` in application directory records suspicious activity
- Detects scanners: 10+ consecutive bad envelopes or stale timestamps -> SCANNER
- Detects unknown message types -> BAD_TYPE (logged immediately)
- Detects high failure rate before disconnect -> SUSPECT
- Log format: `2026-06-23T14:32:01+0000 203.0.113.5:54321 SCANNER (bad_envelope x10)`

**Bootstrap seeds (hardcoded):**
```
wss://bootstrap-eu.gnoppix.org:9001
wss://bootstrap-us.gnoppix.org:9001
wss://bootstrap-asia.gnoppix.org:9001
```

---

### `nat.py` — NAT traversal

STUN-based public endpoint discovery + UDP hole punching.

| Function | Returns | Notes |
|---|---|---|
| `get_public_endpoint(servers)` | `(ip, port) \| None` | Tries multiple STUN servers |
| `hole_punch(local_port, peer_ip, peer_port)` | `socket \| None` | UDP hole punching |

**STUN servers (hardcoded):**
- `stun.l.google.com:19302`
- `stun1.l.google.com:19302`
- `stun2.l.google.com:19302`
- `stun.stunprotocol.org:3478`
- `stun.ekiga.net:3478`
- `stun.ideasip.com:3478`

---

### `ratelimit.py` — rate limiter

Sliding-window rate limiter used by the relay for connection and message
rate limiting per source IP.

```python
class RateLimiter:
    def __init__(self, max_per_window: int, window_sec: float = 60.0)
    def allow(key: str) -> bool
    def prune() -> None
    def start_background_prune(interval: float = 300.0)
    def stop()
```

---

### `client.py` — CLI entry point

Every sub-command maps to a function:

```python
# Synchronous functions:
cmd_init(args)       # generate_keypair() + print
cmd_id(args)         # own_identity() + print
cmd_export(args)     # export_pubkey() + print
cmd_import(args)     # read file or stdin -> import_pubkey()
cmd_contacts(args)   # list_contacts() + print

# Async functions (return coroutine):
cmd_p2p_listen(args) # start P2P node, listen for messages
cmd_send(args)       # start temp P2P node, send message
cmd_chat(args)       # interactive P2P chat session
cmd_dht(args)        # DHT diagnostics (find, advertise)
```

The `main()` function dispatches via a dict lookup and calls
`asyncio.run()` for async commands.

**Adding a new command:**

1. Define the handler function (sync or async).
2. Add a subparser in `main()`.
3. Wire it into `sync_cmds` or `async_cmds` dict.

---

## Cryptographic details

### Key structure (GnuPG 2.5.20 `pqc` algorithm)

```
Primary key: brainpoolP384r1  [SC]  (sign + certify)
     |
Subkey:      ky768_bp256      [E]   (encrypt -- Kyber-768 ML-KEM)
```

`ky768_bp256` = Kyber-768 (NIST security level 3) with brainpoolP256r1
for the ECC component of the hybrid KEM.

### Null ID derivation

```
fingerprint (40 hex chars)
    |
    v
blake2b(digest_size=8)
    |
    v
base32 encoding (lowercase, no padding)
    |
    v
take first 8 chars -> format as NN-XXXX-XXXX
```

This is a one-way mapping. Given a Null ID, the GPG fingerprint cannot be
recovered.

### Encryption format

`gpg --require-pqc-encryption` produces an OpenPGP message containing:

- The session key encrypted with Kyber-768 (ML-KEM encapsulation)
- The plaintext encrypted with AES256 (or the recipient's preferred cipher)

The output is ASCII-armored and safe for JSON transport (after base64
encoding within the envelope).

### Double ratchet (forward secrecy)

Each `PeerConnection` holds a `DoubleRatchetSession` that provides:

- **Forward secrecy:** Each message uses a fresh ephemeral Kyber
  encapsulation. Compromising the long-term key does not reveal past
  session keys.
- **Break-in recovery:** Future messages are safe after compromise.
- **Replay protection:** Sequence numbers + timestamps with 5-minute
  clock skew tolerance.
- **Hash verification:** SHA-256 of ciphertext for integrity + dedup.

Ratchet state is in-memory only. On client restart, a new X3DH handshake
is performed.

---

## Testing

### Crypto unit tests (no relay needed)

```bash
source /tmp/nullnode-venv/bin/activate
python -c "
import crypto
crypto.GPG_HOME = '/tmp/test-gpg'
fp = crypto.generate_keypair()
nid = crypto.null_id(fp)
print(f'Identity: {nid}')
"
```

### E2E test (P2P + DHT, two clients)

```bash
source /tmp/nullnode-venv/bin/activate

# Terminal 1: Alice
export NULLNODE_GNUPGHOME=/tmp/alice
python client.py init
python client.py export > /tmp/alice_pub.asc
python client.py p2p --port 9001

# Terminal 2: Bob
export NULLNODE_GNUPGHOME=/tmp/bob
python client.py init
python client.py export > /tmp/bob_pub.asc
python client.py import /tmp/alice_pub.asc --alias NN-ALICE-ID
python client.py p2p --port 9002

# Back to Alice:
python client.py import /tmp/bob_pub.asc --alias NN-BOB-ID
python client.py send NN-BOB-ID "Hello" --fingerprint BOB_FP
```

### Legacy relay E2E test

```bash
source /tmp/nullnode-venv/bin/activate

# Terminal 1: relay
python relay.py --port 18765

# Terminal 2: Alice
export NULLNODE_RELAY=ws://127.0.0.1:18765
export NULLNODE_GNUPGHOME=/tmp/alice
python client.py init
python client.py export > /tmp/alice_pub.asc

# Terminal 3: Bob
export NULLNODE_RELAY=ws://127.0.0.1:18765
export NULLNODE_GNUPGHOME=/tmp/bob
python client.py init
python client.py export > /tmp/bob_pub.asc
python client.py import /tmp/alice_pub.asc --alias NN-ALICE-ID

# Back to Alice:
python client.py import /tmp/bob_pub.asc --alias NN-BOB-ID
python client.py send NN-BOB-ID "Hello" --fingerprint BOB_FP
```

---

## Roadmap / extension ideas

| Area | Status | What's needed |
|---|---|---|
| **Forward secrecy** | **Implemented** | `DoubleRatchetSession` in crypto.py |
| **Key discovery** | Planned | WKD-style discovery: `openpgpkey.example.com/.well-known/openpgpkey/...` |
| **Tor support** | Planned | Route P2P WebSocket through SOCKS5 (`ws://...onion...`) |
| **TUI client** | Planned | Textual or urwid ncurses interface |
| **Federated relays** | **Implemented** | relay.py: `remote_routes`, gossip, `relay-forward` |
| **Clustering** | Planned | Redis backend for `message_queue` to enable horizontal relay scaling |
| **Binary protocol** | Planned | Replace JSON with CBOR or Protocol Buffers for lower overhead |
| **Key revocation** | Planned | `revoke` command publishing revocation certificate via relay/DHT |
| **DHT mailbox** | **Implemented** | dht.py: `store_mailbox`, `get_mailbox` |
| **DHT address ownership** | **Implemented** | dht.py: `dht-addr-record`, `publish_addr_record`, signature verification |
| **TOFU pinning** | **Implemented** | dht.py: `pin_get`, `pin_update`, `pin_verify_address`, `~/.nullnode/pin_cache.json` |
| **NAT traversal** | **Implemented** | nat.py: STUN + UDP hole punching |
| **Proof-of-work anti-spam** | **Implemented** | protocol.py: `pow_solve`, `pow_check` |

---

## Contribution guidelines

- Keep `crypto.py` pure -- no imports outside `hashlib`, `base64`, `json`,
  `os`, `subprocess`, `secrets`, `hmac`, `time`, `tempfile`. GPG is the
  only crypto provider.
- Every new message type needs a factory method in `protocol.py`, a handler
  branch in the appropriate handler (`relay.py`, `p2p.py`, or `dht.py`),
  and a test.
- Wire format changes must preserve backward compatibility for at least one
  minor version.
- All functions in `crypto.py` must raise `RuntimeError` on GPG failure --
  never let a `CalledProcessError` bubble up.
- All security-sensitive comparisons must use `hmac.compare_digest`.
- DHT writes must include valid proof-of-work.

---

## Environment reference

```
NULLNODE_RELAY          WebSocket URL (legacy relay, default ws://127.0.0.1:8765)
NULLNODE_GNUPGHOME      GPG home directory (default ~/.nullnode/gnupg)
NULLNODE_GPG            Path to gpg binary (default gpg)
NULLNODE_DHT_BOOTSTRAP  Comma-separated bootstrap DHT seeds (default: 3 built-in)
```
