# NullNode

**Post Quantum Encryption, decentalized modern messaging that needs no phone, no email, and no personal information, no company in between.**

Think of it like sending secret notes directly to your friend's house — but the mailman, the post office, and even the government can't read them. NullNode is a messenger that connects you directly to the people you talk to. No company sits in the middle seeing your messages.

Every message is protected by the strongest encryption available today (ML-KEM-1024, the US government's post-quantum standard). Even if someone records everything now and builds a supercomputer in 20 years, they still can't decrypt it.

Sessions persist across restarts — if you receive a message while offline, it gets decrypted and read when you come back.

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

| Binary | Run by | What it does |
|---|---|---|
| `nullnode` | **You** (the user) | Your personal messenger client. You send, read, and receive messages. |
| `nullnode-relay` | **A relay operator** | A store-and-forward server. Holds encrypted messages until the recipient comes online. |
| `nullnode-bootstrap` | **A seed server operator** | The DHT seed node. Clients look it up to find peers. Think of it as the "phone book". |

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

### 7. Listen for incoming P2P connections

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

See [docs/nginx-proxy.md](docs/nginx-proxy.md) for the full nginx config with WebSocket upgrade,
fallback page, and rate limiting.

---

## Three users example

```bash
# Alice creates her identity
./target/release/nullnode init
# => Null ID: NN-ALICE-1111

# Bob creates his identity
./target/release/nullnode init
# => Null ID: NN-BOB-2222

# Carol creates her identity
./target/release/nullnode init
# => Null ID: NN-CAROL-3333

# Alice adds Bob as a contact
./target/release/nullnode add-contact NN-BOB-2222 --fingerprint BOB_FP

# Bob adds Carol as a contact
./target/release/nullnode add-contact NN-CAROL-3333 --fingerprint CAROL_FP

# Alice sends Bob a message (Bob must be running `listen` or have a relay)
./target/release/nullnode send NN-BOB-2222 "Hi Bob!" --fingerprint BOB_FP

# Bob reads his messages
./target/release/nullnode read
```

---

## What is what

```
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│  nullnode   │       │  nullnode   │       │  nullnode   │
│  (client)   │       │  (client)   │       │  (client)   │
│  Alice      │       │  Bob        │       │  Carol      │
└──────┬──────┘       └──────┬──────┘       └──────┬──────┘
       │                     │                     │
       │  P2P direct (when both online)             │
       │─────────────────────│                     │
       │                     │                     │
       │              ┌──────┴──────┐              │
       └──────────────│  nullnode   │──────────────┘
                      │  (relay)    │
                      │  (stores    │
                      │   messages) │
                      └──────┬──────┘
                             │
                      ┌──────┴──────┐
                      │  nullnode   │
                      │ (bootstrap) │
                      │  (DHT seed) │
                      └─────────────┘
```

- **Client (`nullnode`)** — your personal messenger. Manages your keys, sends messages, reads your inbox, listens for incoming connections. Run by every user.
- **Relay (`nullnode-relay`)** — a mailbox server. Stores encrypted messages when the recipient is offline. Anyone can run one; it never sees plaintext (messages are end-to-end encrypted). Run by community operators or your own VPS.
- **Bootstrap (`nullnode-bootstrap`)** — the DHT seed. Clients connect to it first to discover peers and relays. It does NOT handle messages. Usually you use a built-in seed; run your own only for a private network.

---

## Docker

Build and run NullNode as a container (no Rust toolchain needed).

### Build the image

```bash
cd rust
docker build -t nullnode:latest .
```

### Run commands

```bash
# Initialize identity (data persists in volume)
docker run --rm -it -v nullnode-data:/home/nullnode/.nullnode nullnode:latest init

# Show identity
docker run --rm -it -v nullnode-data:/home/nullnode/.nullnode nullnode:latest id

# Send a message
docker run --rm -it -v nullnode-data:/home/nullnode/.nullnode nullnode:latest send NN-THEIR-ID "Hello!" --fingerprint THEIR_FP

# Read messages
docker run --rm -it -v nullnode-data:/home/nullnode/.nullnode nullnode:latest read
```

### Run the relay

```bash
docker run --rm -it -p 8765:8765 nullnode:latest nullnode-relay --host 0.0.0.0 --port 8765
```

### Run the bootstrap DHT seed

```bash
docker run --rm -it -p 9001:9001 nullnode:latest nullnode-bootstrap --host 0.0.0.0 --port 9001
```

### Notes

- The image is ~50 MB (multi-stage build: Rust builder + Debian slim runtime).
- All persistent data lives in `~/.nullnode` — mount a volume to keep it between runs.
- The default entrypoint is `nullnode`. Use `nullnode-relay` or `nullnode-bootstrap` as the command for other binaries.

---

## CLI reference

| Command | Description |
|---|---|
| `init` | Create your identity (generates ML-KEM keypair) |
| `id` | Show your Null ID and fingerprint |
| `export` | Print your public key to share with others |
| `import <file>` | Import a peer's public key |
| `contacts` | List saved contacts |
| `add-contact <NID> --fingerprint <FP>` | Add a contact with verified fingerprint |
| `alias <name> <NID>` | Assign a human-readable name to a Null ID |
| `aliases` | List all aliases |
| `send <NID-or-alias> <msg>` | Send a message |
| `read` | Read messages from relay mailbox + local store |
| `listen` | Start P2P listener for incoming connections |
| `chat <NID>` | Interactive chat session |
| `verify <NID-or-alias>` | Show safety number for out-of-band verification |
| `safety-number <NID-or-alias>` | Show safety number |
| `status` | Show configuration and connection status |

### Bootstrap server flags

| Flag | Default | Description |
|---|---|---|
| `--host` | `0.0.0.0` | Bind address |
| `--port` | `9001` | Bind port |
| `--advertised-url` | (empty) | Public URL (e.g. `wss://bootstrap.example.com/ws`) when behind nginx |
| `--id` | (generated) | Null ID for this node |
| `--db` | `~/.nullnode/bootstrap_dht.db` | SQLite database path |

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `NULLNODE_RELAY` | `ws://127.0.0.1:8765` | Relay URL (fallback) |
| `NULLNODE_DHT_BOOTSTRAP` | (3 built-in seeds) | Comma-separated DHT bootstrap URLs |
| `NULLNODE_USE_TOR` | `false` | Route all traffic through Tor |
| `NULLNODE_TOR_SOCKS` | `socks5://127.0.0.1:9050` | Tor SOCKS5 proxy |
| `NULLNODE_ONION_ADDRESS` | (empty) | Pre-configured .onion address |
| `NULLNODE_ONION_PORT` | `9001` | Port for Tor hidden service |

---

## Documentation

- **[DEVELOPER.md](DEVELOPER.md)** — Architecture, module contracts, ACS2.6 compliance status, coding guidelines
- **[FAQ.md](FAQ.md)** — Common questions about security, encryption choices, and trade-offs
- **[WORKLIST.md](WORKLIST.md)** — Current tasks and implementation progress
- **[CHANGELOG.md](CHANGELOG.md)** — Version history

---

## Supporting the project

Hosting the bootstrap and relay infrastructure costs money. If you find NullNode useful, please consider supporting the project so the servers can keep running.

---

## License

Business Source License (BSL / BUSL).
You can use the code for free, modify it, if you or your company or organisation doesn't have more than 2 people.

---
Copyright (c) 2026 Andreas Mueller — gnoppix.com

