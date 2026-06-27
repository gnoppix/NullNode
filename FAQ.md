# NullNode FAQ

Common questions about NullNode security, encryption choices, and trade-offs.

---

## Why is NullNode different from Signal?

Signal protects your messages too, but it still uses classical encryption (X25519) for most operations. The post-quantum protection only happens at the initial handshake. NullNode uses ML-KEM-1024 (the strongest post-quantum standard) for EVERY message. Even if someone records all traffic now and builds a quantum computer in 20 years, they still can't decrypt it.

Also, Signal routes messages through Google's servers. NullNode connects you directly to your friends — no company in the middle.

---

## Why should I care about post-quantum encryption?

Newer and faster computers (including future quantum computers) will be able to break today's encryption. If someone records internet traffic now, they can decrypt it later when powerful computers exist. NullNode uses encryption that resists even quantum computers.

---

## What is a Null ID and is it private?

Your Null ID (like `NN-XXXX-XXXX`) is a short code derived from your public key. It's safe to share — it doesn't reveal your identity, but it lets people find and message you. Think of it like a phone number that only you can answer.

---

## Do I need to trust any server?

No. The bootstrap seed server only helps you find your friend's address — it never sees your messages. The relay (if used) stores encrypted blobs it cannot read. All encryption and decryption happens on your device.

---

## What if someone steals my phone?

Your keys are stored with 0o600 permissions (only your user can read them). For mobile devices, NullNode supports biometric access lifecycle — keys are scrubbed when the app goes to background or the device locks. This is a future enhancement.

---

## Can the government read my messages?

No. The content is encrypted with ML-KEM-1024 + AES-256-GCM. The government would need to break the math behind these algorithms, which is believed to be impossible even for supercomputers.

What they CAN see (if you don't use Tor): that you're running NullNode, when you connect, and how much data you transfer. Tor hides this.

---

## Why is there no group messaging yet?

Post-quantum group messaging requires ML-DSA-87 signing (PQ-Sender Keys), which is more complex to implement. It's planned in the ACS2.6 specification but not yet implemented. For now, NullNode supports 1-to-1 messaging only.

---

## What happens if I lose my identity?

Run `nullnode export` to save your public key. Share it with contacts so they can still verify your identity. Your private key stays on your device — if you lose the device, you need to generate a new identity and have contacts verify the new one.

---

## How do I know someone isn't impersonating my contact?

NullNode shows a **safety number** — a deterministic code derived from both parties' fingerprints. Compare it out-of-band (in person, voice call, PGP-signed email). If the numbers match, no one is intercepting your communication.

---

## Why is I2P not supported?

NullNode follows a Tor-first approach. I2P support is planned but requires additional dependencies and architectural changes. For now, Tor provides IP-level privacy when enabled.

---

## Why Argon2id instead of SHA-256 for proof-of-work?

SHA-256 hashcash is trivially GPU-accelerated. A single RTX 4090 can compute ~10 billion SHA-256 hashes/second. Argon2id is memory-hard: each instance requires 16MB of RAM. A 24GB GPU can only run ~1,500 parallel instances, each taking ~0.5s. This reduces botnet throughput by ~500,000x.

---

## What's the centralized seed model? Why not full Kademlia?

Instead of full Kademlia DHT routing (which requires complex routing table maintenance), NullNode uses centralized bootstrap seeds as authoritative directories. This is:
- Simpler to implement and audit
- More reliable (no routing table maintenance, no lookup latency)
- Sufficient for current scale

Full Kademlia routing is a future enhancement.

---

## How does the relay federation work?

Multiple relays can form a network where messages route between them. Each relay maintains a list of which Null IDs it serves locally and which are reachable via peer relays. Messages can traverse up to 5 relay hops with loop detection. Peer connections are authenticated with HMAC-SHA256 using a shared secret.

---

## What data does the relay see?

The relay sees: sender Null ID, receiver Null ID, connection timestamps, and message size. It does NOT see message content (encrypted before leaving the client). Route through Tor to obscure IP metadata.

---

## What happens when I receive a message while offline?

When you're offline, messages are stored encrypted on the relay. When you run `nullnode read`, the client fetches those offline messages and decrypts them using your persisted DoubleRatchet sessions. The session state is updated after decryption, so future messages from the same contact continue to work correctly.

If this is your first conversation and the session was created when the message arrived (e.g., someone sent you a message and you received it via relay before ever connecting directly), the session has already been initialized and decryption works transparently.

---

## Is my GPG private key stored safely on disk?

Yes. Starting from v0.2.4, your GPG secret key is encrypted at rest using age passphrase encryption (scrypt + XChaCha20-Poly1305). You set the passphrase during `nullnode init`. On startup, the client prompts you to enter it before the key is decrypted into memory.

If you prefer not to set a passphrase, press Enter at the prompt — the key will be stored as plaintext (previous behavior). Backward compatibility with existing plaintext `own_cert.asc` files is preserved.

---

## How does message delivery work?

NullNode uses a two-tier delivery system: **direct P2P** when the recipient is online, and **relay mailbox** when they're offline.

### Direct P2P delivery (primary)

When you send a message:

1. The recipient's address is looked up in the DHT (bootstrap seed).
2. A direct WebSocket connection is established to the recipient's P2P listener.
3. A handshake exchanges Kyber-1024 public keys and proves identity via GPG signatures.
4. Messages are encrypted with the Double Ratchet algorithm (ML-KEM + AES-256-GCM) and sent directly.
5. The recipient decrypts immediately and sends back two confirmations:
   - `p2p-ack` — transport-level confirmation (message received)
   - `p2p-receipt` — cryptographic E2E confirmation (message decrypted and read)

You see `"Message delivered successfully!"` on ack, and `"Message READ by peer at HH:MM:SS [E2E confirmed]"` on receipt.

### Relay mailbox (fallback)

If the recipient is offline or unreachable via P2P, the message is stored encrypted on the relay:

1. The sender stores the encrypted message in the recipient's relay mailbox.
2. When the recipient comes online and runs `nullnode read`, the client fetches all stored messages.
3. Messages are decrypted using the persisted Double Ratchet session.
4. After successful fetch and decryption, the client sends a `relay-purge` command to delete all messages from the mailbox. This prevents stale ciphertext from accumulating.

### Delivery confirmation levels

| Level | What it proves | How it's verified |
|---|---|---|
| Relay stored | Message reached the relay | Relay returns `"ok"` |
| P2P ack | Message reached the peer over WebSocket | Signed `p2p-ack` received |
| P2p-receipt | Peer decrypted the message | Signed `p2p-receipt` with recipient's GPG key |

### Edge-core relay mode

Relays can run in two modes:

- **Core mode** (`--allow-relay`): accepts and forwards messages between other relays (federation transit). This is the default for server-side relays.
- **Edge mode** (default, no `--allow-relay`): only serves its own local mailboxes. Refuses to forward messages on behalf of other relays. This is appropriate for mobile or battery-powered nodes running a local relay.

Edge mode prevents mobile nodes from being used as transit points in the relay federation, saving battery and bandwidth.

---

## Documentation

- **[README.md](README.md)** — Project overview and quick start
- **[DEVELOPER.md](DEVELOPER.md)** — Architecture, module contracts, ACS2.6 compliance
- **[WORKLIST.md](WORKLIST.md)** — Current tasks and progress
- **[CHANGELOG.md](CHANGELOG.md)** — Version history

---

## License

Business Source License (BSL / BUSL).
You can use the code for free if your company or organisation doesn't have more than 2 people.
