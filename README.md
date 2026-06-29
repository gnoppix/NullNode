# NullNode

**Post Quantum Encryption, decentralized modern messaging that needs no phone, no email, and no personal information, no company in between.**

Think of it like sending secret notes directly to your friend's house — but the mailman, the post office, and even the government can't read them. NullNode is a messenger that connects you directly to the people you talk to. No company sits in the middle seeing your messages.

Every message is protected by the strongest encryption available today (ML-KEM-1024, the US government's post-quantum standard). Even if someone records everything now and builds a supercomputer in 20 years, they still can't decrypt it.

Sessions persist across restarts — if you receive a message while offline, it gets decrypted and read when you come back.

---

## What's new in v0.3.9

- **Bidirectional E2E encryption** — Full bidirectional Double Ratchet encryption verified end-to-end. Initiator and responder can both send and receive encrypted messages through the relay, with the ratchet advancing correctly in both directions.
- **Wire format fix** — Corrected the Kyber ciphertext length field placement in `encrypt_message()` to match what `decrypt_message()` expects. This was causing AES-GCM decryption failures when the responder replied to the initiator.
- **Regression test** — Added `test_bidirectional_ratchet_roundtrip` to prevent this class of bug from recurring.

---

## How it works (the short version)

1. You run `nullnode init` — it creates a unique "key" (like a lock with two halves).
2. The public half becomes your **Null ID** — something like `NN-XXXX-XXXX`. Share this with friends so they can find you.
3. When you send a message, it gets locked with your friend's key and travels directly to them.
4. If they're offline, the message waits in a locked mailbox (the DHT) until they come back online.

It's like BitTorrent, but for private messaging.

---

## Quick start

NullNode has three binaries. Each is run by a different role:

|| Binary | Run by | What it does |
||---|---|---|
|| `nullnode` | **You** (the user) | Your personal messenger client. You send, read, and receive messages. |
|| `nullnode-relay` | **A relay operator** | A store-and-forward server. Holds encrypted messages until the recipient comes online. |
|| `nullnode-bootstrap` | **A seed server operator** | The DHT seed node. Clients look it up to find peers. Think of it as the "phone book". |

### 1. Build everything

```bash
cd rust
make all
```

This produces three binaries in `target/release/`:
- `nullnode`       — the client
- `nullnode-relay` — the relay server
- `nullnode-bootstrap` — the DHT seed server

### 2. A user creates their identity

```bash
./target/release/nullnode init
```

This creates `~/.nullnode/` with your ML-KEM keypair and prints your Null ID:

```
Null ID: NN-A1B2-C3D4
Fingerprint: ABCD1234...
```

Share your Null ID with friends so they can send you messages. Share your **fingerprint** with contacts so they can verify your identity.

### 3. Show your ID anytime

```bash
./target/release/nullnode id
```

### 4. Add a contact

```bash
./target/release/nullnode add-contact NN-E5F6-G7H8 --fingerprint THEIR_FINGERPRINT
```

### 5. Add an alias (optional, for convenience)

```bash
./target/release/nullnode alias Bob-office NN-E5F6-G7H8
```

Aliases map a short human-readable name to a Null ID. You can then use the alias everywhere a Null ID is expected.

### 6. Send a message

```bash
# Using the Null ID directly (always works)
./target/release/nullnode send NN-E5F6-G7H8 "Hello, Bob!"

# Using the alias (easier to remember)
./target/release/nullnode send Bob-office "Hello, Bob!"
```

### 6. Read your messages

```bash
./target/release/nullnode read
```

### 7. Register identity with DHT

If your identity was created while the bootstrap was unreachable, register it explicitly:

```bash
./target/release/nullnode register
```

This sends your Null ID and fingerprint to the bootstrap DHT so others can find you.

### 8. Listen for incoming P2P connections

```bash
./target/release/nullnode listen
```

---

## Running a server

### Relay server (anyone can run one)

```bash
./target/release/nullnode-relay --host 0.0.0.0 --port 8765
```

Clients connect to this relay to store and fetch messages when the other party is offline.

### Bootstrap DHT seed (usually only a few trusted operators)

```bash
./target/release/nullnode-bootstrap --host 0.0.0.0 --port 9001
```

Clients use this to discover peers and find relay servers. The default `NULLNODE_DHT_BOOTSTRAP` env var points to built-in seeds — you only need to run your own if you want to operate independent infrastructure.

### Behind nginx (TLS on :443)

For production deployments, run the bootstrap behind nginx to get TLS 1.3 on port 443:

```bash
# Bootstrap binds to localhost only — nginx terminates TLS and forwards
./target/release/nullnode-bootstrap \
    --host 127.0.0.1 --port 9001 \
    --advertised-url wss://bootstrap.example.com/ws
```

The bootstrap will automatically use stable IDs (auto-generated Kyber-1024 keypair if no GPG key exists) and operate in "proxy mode" (no TLS warning when `--host` is `127.0.0.1`).

For direct TLS mode (when NOT behind nginx), provide certificates:

```bash
./target/release/nullnode-bootstrap \
    --host 0.0.0.0 --port 443 \
    --tls-cert /etc/letsencrypt/live/bootstrap.example.com/fullchain.pem \
    --tls-key /etc/letsencrypt/live/bootstrap.example.com/privkey.pem
```

See [docs/nginx-proxy.md](docs/nginx-proxy.md) for the full nginx config with WebSocket upgrade,
fallback page, and rate limiting.

---

## Three users example

TODO: Add example with 3 users, relays, and bootstrap coordination.