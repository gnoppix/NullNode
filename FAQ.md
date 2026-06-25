## How does the bootstrap server TLS work?

Bootstrap servers speak TLS directly on their listen port (no reverse
proxy needed). The client verifies the certificate using rustls with the
native root store (WebPKI verifier).

```bash
# Start bootstrap with TLS (cert files provided at runtime)
./target/release/nullnode-bootstrap --host 0.0.0.0 --port 9001
```

The client verifies the cert against `~/.nullnode/bootstrap_pin_cache.json`
(TOFU) and checks domain (*.gnoppix.org / *.gnoppix.com) and CA (Let's Encrypt).

## How does the client verify the bootstrap server's identity?

On every connection to a bootstrap seed, the client performs 5 checks:

1. **Cert fingerprint (TOFU pin)** -- first-seen cert is pinned to
   `~/.nullnode/bootstrap_pin_cache.json`. Same cert = accept. Changed cert =
   check rotation rules.
2. **Cert validity window** -- accepts rotation if cert is currently valid
   AND was issued within 90 days (Let's Encrypt cycle). This handles long
   offline periods (100+ days).
3. **Domain check** -- cert SAN/CN must match `*.gnoppix.org` or
   `*.gnoppix.com`. Prevents attacker from using their own domain.
4. **CA check** -- cert issuer must be Let's Encrypt / ISRG. Prevents
   attacker from using a valid cert for our domain obtained from a
   compromised/rogue CA.
5. **TOFU rotation rules** -- if cert changed and validity window check
   fails, falls back to pin age (< 90 days = accept, >= 90 days = reject).

If all checks pass, the client trusts the bootstrap for DHT queries.

## What if the bootstrap server's Let's Encrypt cert rotates while I'm offline?

The client accepts rotation if the new cert is currently valid AND was
issued within the last 90 days. Let's Encrypt renews every 60-80 days, so
even if you're offline for 100 days, the new cert is within its validity
window and accepted automatically.

If the cert changes after 90+ days of being offline, the client rejects it
(possible MITM). Delete `~/.nullnode/bootstrap_pin_cache.json` to reset TOFU
and re-trust the new cert.

## How does bot/scanner detection work?

Suspicious connections are logged to `bot_connection.log` in the
application directory. The log detects:

- **SCANNER**: 10+ consecutive bad envelopes or stale timestamps
- **BAD_TYPE**: Unknown message types sent to the DHT port
- **SUSPECT**: 5+ consecutive failures before disconnect

Log format: `2026-06-23T14:32:01+0000 203.0.113.5:54321 SCANNER (bad_envelope x10)`

This helps identify port scanners, vulnerability probes, and misconfigured
clients hitting the bootstrap server.

## How does the bootstrap server protect against rogue CAs?

Even if an attacker obtains a valid cert for `*.gnoppix.org` from a
compromised or rogue CA, the client checks the cert's issuer. Only
certificates chaining to Let's Encrypt / ISRG are accepted. An attacker
with a cert from their own CA (or a different CA) is rejected.

Additionally, the TOFU pin means the client remembers the cert fingerprint
from the first legitimate connection. Any subsequent cert change must pass
the rotation rules (validity window + pin age), making it extremely hard
for an attacker to substitute certs even with a valid cert for the domain.

## Why Argon2id instead of SHA-256 for PoW?

SHA-256 hashcash is trivially GPU-accelerated. A single RTX 4090 can compute
~10 billion SHA-256 hashes/second, making difficulty 16 (~65k attempts) take
0.0065ms. A botnet of 10,000 GPUs could flood 1.5 billion DHT writes/sec.

Argon2id is memory-hard: each instance requires 16MB of RAM. A 24GB GPU can
only run ~1,500 parallel instances, each taking ~0.5s. This reduces botnet
throughput to ~3,000 writes/sec per GPU -- a 500,000x reduction.

Argon2id is also the standard for password hashing (RFC 9106) and is
well-audited. The fallback to SHA-256 exists if the argon2 Rust crate
is unavailable.

## Why STUN exists in NullNode

STUN lets a client behind a NAT/router discover its public IP:port as seen
from the internet. This is needed for direct P2P connections:

```
Alice (behind NAT)              Bob (behind NAT)
  192.168.1.5:4567  ──────►  ???  (Bob can't reach Alice)

Alice asks STUN server:
  "what address do you see me as?"
  STUN replies: "203.0.113.42:51234"

Alice now knows her public endpoint.
She can share it in the DHT so Bob can connect.
```

The flow is: STUN -> discover public endpoint -> advertise in DHT -> other
peers connect via that endpoint.

**Recommendation**: For a privacy-first messenger, STUN should be opt-in
(not enabled by default) since it leaks your IP to the STUN server.
Alternatively, use Tor and skip STUN entirely.

## How does contact verification (safety numbers) work?

NullNode implements safety number verification (G6) analogous to Signal's
safety number. When you add a contact, a deterministic "safety number" is
computed from both parties' fingerprints:

1. Both fingerprints are sorted lexicographically
2. Concatenated with `|` separator
3. SHA-256 hashed
4. Formatted as 8 groups of 8 hex chars for easy visual comparison

Both parties will always get the same safety number regardless of who
initiated. If the safety numbers differ, a man-in-the-middle attack may be
underway. Always verify safety numbers out-of-band (in-person, voice call,
PGP signed email) before trusting a contact.

## Why is Kademlia DHT routing not implemented (G4)?

NullNode uses a **centralized seed model** instead of full Kademlia DHT routing.
Bootstrap seeds act as authoritative directories -- clients query the seed to
find peer addresses, then connect directly.

**Trade-off**: The centralized seed is a single point of failure and requires
trusted infrastructure. However, it is:
- Simpler to implement and audit
- More reliable (no routing table maintenance, no lookup latency)
- Sufficient for the current scale

Full Kademlia routing (K-buckets, alpha lookups, FIND_NODE/FIND_VALUE RPCs)
is a future enhancement. The current model provides the same end-user
experience (direct P2P messaging) with less complexity.

## How does relay federation work?

Multi-relay federation allows multiple relays to form a network where messages
can be forwarded between peers. Each relay maintains:

- **local_sessions**: Null IDs of directly-connected clients
- **remote_routes**: Null IDs reachable via peer relays (learned through gossip)

When a relay receives a message for a Null ID in its `remote_routes`, it wraps
the message in a `relay-forward` envelope and sends it to the peer relay.
The forwarding relay increments `hop_count` and appends its URL to the `via`
chain for loop detection (max 5 hops).

**Security**: Peer connections are authenticated with HMAC-SHA256
challenge-response using a shared secret (`--secret-file`). Only relays
knowing the shared secret can exchange routes and forward messages.

**Performance**: Route advertisements are sent every 60 seconds. Routes expire
after 30 minutes of inactivity. A background gossip task handles maintenance.

## Why is I2P transport not implemented (G8)?

NullNode follows a **Tor-first approach** for transport-level anonymity.
I2P support is planned as a future transport option but requires:
- Additional dependencies (`i2p` crate or SAM bridge integration)
- Significant architectural changes to the transport layer
- Separate key management (I2P destination keys vs Tor hidden service keys)

The current transport layer supports:
- Direct TCP connections
- Tor SOCKS5 proxy (via `socks` crate)
- Onion address validation (`.onion` TLD detection)

I2P integration is deferred per the project's incremental approach: Tor first,
I2P later.

## How does key persistence work (G9, G10)?

**Kyber-768 keypair persistence (G10):**
- Keys are saved to `~/.nullnode/kyber_keys.json` as hex-encoded JSON
- File permissions: 0o600 (owner-only read)
- Uses `KeyExport::to_bytes()` for canonical byte representation
- `load_or_generate()` convenience: loads if file exists, generates + saves if not
- This ensures your DHT address (derived from your public key) stays stable
  across restarts

**Double ratchet session persistence (G9):**
- Sessions are saved to `~/.nullnode/ratchet_sessions/` as JSON files
- File permissions: 0o600 (owner-only read)
- Preserves all session state: keys, sequence numbers, pending messages,
  timestamps
- Uses `serialize()`/`deserialize()` for JSON conversion
- This ensures encrypted conversations survive restarts without re-keying
