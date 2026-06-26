# NullNode

**Post Quantum Encryption, decentalized modern messaging that needs no phone, no email, and no personal information, no company in between.**

Think of it like handing a secret note directly to your friend, where the mailman, the post office, and the government are entirely locked out. NullNode is a peer-to-peer messenger that connects you directly to your contacts without any company sitting in the middle. No one can see who you are messaging, sharing files with, or calling. Your metadata is completely hidden. It isn't just the initial handshake that is post-quantum encrypted—everything is. If an adversary monitors your connection, they will only see the amount of data being transferred and nothing more. For deeper technical details, refer to the developer documentation.


Every message is protected by the strongest encryption available today (ML-KEM-1024, the US government's post-quantum standard). Even if someone records everything now and builds a supercomputer in 20 years, they still can't decrypt it.

---

## How it works (the short version)

1. You run `nullnode init` — it creates a unique "key" (like a lock with two halves).
2. The public half becomes your **Null ID** — something like `NN-XXXX-XXXX`. Share this with friends so they can find you.
3. When you send a message, it gets locked with your friend's key and travels directly to them.
4. If they're offline, the message waits in a locked mailbox (the DHT) until they come back online.

It's like BitTorrent, but for private messaging.

---

## Quick start

```bash
cd rust
make all
./target/release/nullnode init
```

This creates your identity. Share your Null ID (`NN-XXXX-XXXX`) with contacts.

### Two users example

```bash
# Alice creates an identity
./target/release/nullnode init

# Bob creates an identity
./target/release/nullnode init

# Alice sends to Bob
./target/release/nullnode send NN-BOB-ID "Hello!" --fingerprint BOB_FP
```

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
| `send <NID> <msg>` | Send a message |
| `read` | Read messages from relay mailbox + local store |
| `listen` | Start P2P listener for incoming connections |
| `chat <NID>` | Interactive chat session |
| `verify <NID>` | Show safety number for out-of-band verification |
| `safety-number <NID>` | Show safety number |
| `status` | Show configuration and connection status |

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

