# Changelog

## 2026-06-23

### Added
- **Native TLS support for DHT bootstrap servers** (`dht.py`, `bootstrap_server.py`)
  - `DHTNode.__init__()` accepts `ssl_certfile` and `ssl_keyfile` params
  - `DHTNode.start()` creates an `ssl.SSLContext` when both are provided, passes it to `websockets.serve()`
  - Address scheme is now `wss://` when TLS is active, `ws://` otherwise (no more hardcoded `wss://`)
  - `create_dht_node()` factory forwards the new TLS params
  - `bootstrap_server.py` reads `NULLNODE_BOOTSTRAP_CERT` and `NULLNODE_BOOTSTRAP_KEY` env vars
  - No reverse proxy needed -- bootstrap server speaks TLS directly on its listen port
  - Fully backward compatible: without cert env vars, falls back to plain `ws://`

### Fixed
- **Bootstrap server address scheme always showed `wss://` even without TLS** (`bootstrap_server.py`)
  - Log message now reflects actual scheme based on whether cert files are configured

## 2026-06-22 (cont.)

### Fixed
- **nullnode.sh used hardcoded `/tmp/nullnode-venv` ignoring local `./venv`** (`nullnode.sh`)
  - When `install.sh` created a `./venv` alongside the source, `nullnode.sh` still used `/tmp/nullnode-venv` which lacked `websockets`
  - Fixed: now prefers local `./venv` if present, falls back to `/tmp/nullnode-venv`
- **Base64 `Incorrect padding` crash on mailbox poll and P2P messages** (`p2p.py`)
  - `base64.b64decode()` calls on network-received data (mailbox blobs, P2P ciphertext, handshake public keys) failed with `Incorrect padding` when data lacked `=` padding
  - Fixed: all 5 `b64decode` call sites now pad input to a multiple of 4 and wrap in try/except with warning logs instead of crashing

### Changed
- **Source header updated** (all 10 code files)
  - Date range corrected from `2002-2006` to `2002-2026`
  - Added free-use license line: "You can use the code for free if your company or organisation doesn't have more than 2 people."
- **install.sh rewritten as standalone curl-pipe bootstrap** (`install.sh`)
  - Can be used via `curl -fsSL https://raw.githubusercontent.com/gnoppix/NullNode/main/install.sh | bash`
  - Downloads full source from GitHub (tarball → git clone → individual files fallback)
  - Re-executes from downloaded copy for proper path resolution
  - `--no-download` flag for running from an already-cloned repo

## 2026-06-22

### Security
- **DHT address ownership verification** (`dht.py`, `protocol.py`)
  - New `dht-addr-record` message type: publisher signs `null_id|address|ttl`
  - Signature verified against publisher's GPG fingerprint
  - `null_id` must equal `compute_null_id(publisher_fp)` (proves key ownership)
  - Stored in DHT with `addr:` salt prefix to distinguish from mailbox data
  - `DHTNode._handle_addr_record()` validates and stores signed records
  - `DHTNode.publish_addr_record()` creates signed address records
  - `DHTNode.lookup()` validates address signature before returning result
- **TOFU pinning** (`dht.py`)
  - First address received for a null_id is trusted and pinned to disk
  - Pin cache at `~/.nullnode/pin_cache.json`
  - `pin_get()`, `pin_update()`, `pin_verify_address()` functions
  - Subsequent addresses must match the pin; mismatches rejected with warning
- **P2P connection validation** (`p2p.py`)
  - `_try_connect()` validates address against TOFU pin before connecting
  - `_handle_connection()` validates incoming connection source against pin
  - Both reject on mismatch (possible MITM)
  - `start()` now uses `publish_addr_record()` (signed) instead of `advertise_address()`

### Security fixes (audit round 2)
- **CRITICAL: Signature verification did not bind to expected fingerprint** (`crypto.py`)
  - `verify_signature()` called `gpg --verify` which validated ANY valid signature
  - An attacker with ANY GPG key in the keyring could forge messages
  - Fixed: now parses `--status-fd` output to extract signing key fingerprint
  - Comparison uses constant-time comparison to prevent timing attacks
- **CRITICAL: Mailbox sender identity not authenticated** (`p2p.py`)
  - `signed_blob` format was `ct_b64|sender_nid|sig` -- `sender_nid` was NOT
    covered by the signature, allowing sender impersonation
  - Fixed: format is now `ct_b64|sender_nid|sender_fp|sig`
  - Signature now covers `sender_fp|recipient_nid|ct_b64|seq`
  - `_poll_mailbox()` now verifies sender signature before delivering message
  - Legacy unsigned blobs are rejected (no sender authentication = no delivery)
- **HIGH: Unsigned DHT results accepted for address lookups** (`dht.py`)
  - `lookup()` accepted unsigned (non-addr:) results and pinned them on first use
  - An attacker running a malicious DHT node could return fake addresses
  - Fixed: unsigned results are now rejected with a warning
  - Only signed `addr:` records with valid signatures are accepted
- **MEDIUM: No first-contact warning** (`dht.py`, `p2p.py`)
  - First contact (no prior TOFU pin) was silently accepted
  - Fixed: prominent `FIRST CONTACT` warning logged on first contact
  - Both DHT lookup and P2P connection paths warn the user
  - User should verify the address out-of-band before trusting
- **LOW: Bot/scanner detection** (`dht.py`, `p2p.py`)
  - Port scanners and bots probing random WebSocket ports receive clear error messages
  - Added `NULLNODE_STEALTH` environment variable to enable stealth mode
  - In stealth mode, non-clients receive ambiguous responses (e.g., "HTTP/1.1 400 Bad Request")
  - This prevents scanners from identifying NullNode nodes via protocol fingerprinting
- **BUG: P2P node published unreachable `wss://0.0.0.0` address** (`p2p.py`)
  - `P2PNode.start()` published `wss://0.0.0.0:<port>` as its DHT address
  - Remote peers trying to connect to `0.0.0.0` would hit their own machine, not us
  - Fixed: now uses STUN (`nat.get_public_endpoint()`) to discover public IP:port
  - Falls back to `0.0.0.0` only if STUN fails (with a warning)
  - This was the last remaining dead-code path for `nat.py` — now it's active

### Documentation
- **README.md** — fully rewritten to match current P2P + DHT architecture
  - Removed all references to non-existent `listen` command
  - Quick start now uses `p2p` + DHT flow instead of relay-based flow
  - Added P2P node section, DHT diagnostics, NAT traversal docs
  - Updated CLI reference with `p2p`, `dht` commands
  - Added P2P wire protocol and DHT mailbox protocol diagrams
  - Updated topology comparison (P2P + DHT is now default)
  - Forward secrecy marked as implemented (was "not yet implemented")
  - Added `NULLNODE_DHT_BOOTSTRAP` env var to reference
- **FEATURES.md** — updated to match actual codebase
  - Setup section uses `p2p` command instead of non-existent `listen`
  - Quick start rewritten for P2P + DHT flow
  - Added "Running a Legacy Relay (Fallback)" section
  - Added DHT address ownership verification and TOFU pinning to security hardening
  - Message flow updated with signature verification and TOFU pin steps
  - Environment variables table includes `NULLNODE_DHT_BOOTSTRAP`
  - Forward secrecy description updated to reflect double ratchet implementation
- **DEVELOPER.md** — expanded to cover all 8 source modules
  - Project layout now lists all .py files (p2p, dht, nat, ratelimit added)
  - Added full module contracts for `p2p.py`, `dht.py`, `nat.py`, `ratelimit.py`
  - `crypto.py` contract updated with all missing functions and `DoubleRatchetSession`
  - `protocol.py` contract updated with all 24 message types (was 7)
  - `relay.py` contract updated with federation, rate limiting, new constants
  - `client.py` contract: `cmd_listen` replaced with `cmd_p2p_listen`, added `cmd_dht`
  - Added double ratchet section to cryptographic details
  - Added DHT address ownership verification and TOFU pinning sections
  - E2E test updated to P2P flow; legacy relay test kept as secondary
  - Roadmap updated: forward secrecy, federated relays, DHT, NAT, PoW, address ownership, TOFU pinning marked implemented
  - Contribution guidelines expanded with `hmac.compare_digest` and DHT PoW rules
  - Environment reference includes `NULLNODE_DHT_BOOTSTRAP`
- **nullnode.sh** — removed non-existent `listen`, `connect`, `listen-p2p` commands
  - Valid commands now match `client.py`: `relay|init|id|export|import|contacts|send|chat|p2p|dht`
- **Dockerfile** — added missing `ratelimit.py`, `nat.py`, `relay.py` to COPY line
  - Without these, Docker builds would fail with `ModuleNotFoundError` at runtime

## 2026-06-20

### Added
- **Hardcoded bootstrap seeds for zero-config internet discovery** (`dht.py`)
  - `BOOTSTRAP_SEEDS` — 3 well-known master node URLs for initial DHT bootstrapping
  - Used as fallback when no CLI arg, env var, cache, or DNS seeds are available
  - Clients update routing table immediately after discovering any seed
- **Active routing table maintenance** (`dht.py`)
  - `_evict_stale()` — pings LRU node per bucket in parallel; removes unresponsive ones
  - `_refresh_bucket()` — picks random ID in a bucket's range, does `FIND_NODE` to discover new peers
  - Bucket refresh rotates every 60s across all buckets; full eviction cycle every hour
- **Advertise on routing table growth** (`dht.py`)
  - `_known_nodes` counter tracks routing table size in the 60s maintenance loop
  - When new nodes are discovered (via queries, lookups, or incoming connections), a re-advertisement is triggered immediately (up to 60s delay)
  - Ensures address is always pushed to the current K closest nodes, not just the bootstrap-time set
- **DNS SRV fallback discovery** (`dht.py`)
  - `resolve_bootstrap_dns()` — tries `dig SRV _nullnode-dht._tcp.gnoppix.org` first
  - Falls back to A/AAAA resolution of seed hostnames
  - No extra dependencies required (`dig` optional; system resolver handles fallback)
- **`cmd_dht --advertise` accepts optional relay URL** (`client.py`)
  - `--advertise` now supports `nargs="?"`: `nullnode dht --advertise ws://1.2.3.4:9001`
  - Without argument, behaves as before (advertises own DHT address)
- **`listen-p2p --public-addr` and `--dht-port` for public servers** (`client.py`)
  - `--public-addr` sets the advertised relay URL to the server's public hostname/IP
  - `--dht-port` allows setting a fixed DHT port (default: random)
  - DHT node's own address is also set to the public hostname so remote nodes can route queries back
- **DDoS / abuse hardening for public ports** (`relay.py`, `dht.py`, `ratelimit.py`)
  - Added shared `RateLimiter` utility with sliding-window per-IP rate limiting
  - Relay hardening: connection rate limit (50/min), message rate limit (120/min), max sessions per NID (10), max total queue (10,000), max message size (1MB), max peer relays (20)
  - DHT hardening: connection rate limit (50/min), query rate limit (200/min), max store entries (5,000), max store per IP (100), max value size (1KB)
  - WebSocket protocol-level rejection for oversized messages (1009 error)
  - Focused tests passed for relay and DHT hardening separately

### Fixed
- **Domain `nullnode.net` → `gnoppix.org`** (`dht.py`, `README.md`, `CHANGELOG.md`)
  - Updated BOOTSTRAP_SEEDS hostnames and SRV DNS record target
- **`listen-p2p` advertised `ws://127.0.0.1` — unreachable from remote peers** (`client.py`, `dht.py`)
  - DHT advertised URL was hardcoded to loopback; added `--public-addr` flag
  - DHT node's own address was `ws://0.0.0.0:<random>` — also unreachable
  - Now overridable via `--public-addr` and `--dht-port`
  - `advertise_address` now also stores the advertisement locally so self-lookup works
- **Federation: queued messages not forwarded when route appears late** (`relay.py`)
  - Added `_drain_queue(nid, relay_url)` — forwards queued messages when a route is learned
  - `route-advertise` handler now drains queue for each newly learned route
  - `route-found` handler also drains queue after learning a route
  - Message is no longer stuck forever if the recipient's relay wasn't known at send time

- **Federation: route-advertise not broadcast on client registration** (`relay.py`)
  - Added `_broadcast_routes()` — sends current route table to all peer relays
  - Called immediately in `_connect_peer_relay` after connecting
  - Called when a new client registers (`register` handler)
  - Gossip interval (60s) was too slow for timely route propagation

- **Federation: incoming peer connections not tracked** (`relay.py`)
  - Added `_register_peer_ws()` — records incoming WebSocket as a peer relay
  - `handle_client` now detects `route-advertise` as the first message from a peer → treats connection as a relay peer
  - Both directions (outgoing `_connect_peer_relay` + incoming `handle_client`) are now tracked in `peer_relays`

- **Federation: peer reconnection** (`relay.py`)
  - Added `_peer_reconnect_loop` — retries failed peer connections every 30s
  - Without this, a relay that started before its peer would never connect

- **DHT: bootstrap returning empty routing table** (`dht.py`)
  - `find-node` handler now includes the responding node itself in `closer-nodes` (was omitted when routing table was empty, preventing new nodes from joining)
  - Same fix applied to `find-value` handler

- **DHT: lookup returns None by checking network only** (`dht.py`)
  - `lookup()` now checks local `store` dict before querying the network
  - Prevents unnecessary network queries when the value is cached locally

- **DHT: mDNS blocking asyncio event loop** (`dht.py`)
  - `_register_mdns()` and `discover_mdns_async()` now use `loop.run_in_executor()` for `Zeroconf()` calls
  - `Zeroconf()` is a synchronous constructor that blocks; running it in a thread avoids freezing the event loop

- **DHT: self-discovery via mDNS** (`dht.py`)
  - `create_dht_node` now filters out own address from mDNS-discovered seeds
  - `_register_mdns` runs as a background task (not awaited), so the node might discover its own mDNS registration
  - Filtered via `seeds = [a for a in mdns_addrs if a != node.address]`

- **DHT: bootstrap race condition** (`dht.py`)
  - `bootstrap()` now retries 2x with 0.5s delay between attempts
  - On first run, the websocket server may not be fully listening when `create_dht_node` calls bootstrap — retry handles this

- **Crypto: GPG_HOME not re-evaluated on env var change** (`crypto.py`)
  - `GPG_HOME` was a module-level constant evaluated once at import time
  - Changed to `_gpg_home()` function that reads `os.environ` dynamically
  - This broke all multi-identity operations (importing contacts, switching between Alice/Bob in tests)

### Added
- **DHT peer persistence** (`dht.py`)
  - `load_peers_cache()` / `save_peers_cache()` — persist known DHT nodes to `~/.nullnode/peers.json`
  - `save_peers_cache()` is called in `DHTNode.stop()`
  - On startup, `create_dht_node` loads cached peers as bootstrap seeds if no explicit bootstrap given

- **mDNS discovery (optional, requires `zeroconf`)** (`dht.py`)
  - `discover_mdns_async()` — browses `_nullnode-dht._tcp.local.` for DHT peers
  - `_register_mdns()` — advertises this node as a DHT peer via mDNS
  - mDNS is used as a fallback when no bootstrap nodes or cached peers are available

- **Auto-discovery in client commands** (`client.py`)
  - `_discover_relay(nid)` — bootstraps DHT, looks up a NID, returns their relay URL
  - `cmd_send` without `--relay` now auto-discovers the recipient's address via DHT
  - `cmd_chat` without `--relay` same auto-discovery
  - `cmd_connect` without `--address` same auto-discovery
  - `cmd_listen_p2p` now starts a DHT node and advertises the relay address (opt-out via `--no-dht`)

- **`advertise_address(advertise_addr=...)` parameter** (`dht.py`)
  - Allows storing a custom address (relay URL) instead of the DHT node's own address
  - Used by `cmd_listen_p2p` to advertise the relay port, not the DHT port

- **`--no-dht` flag on `listen-p2p`** (`client.py`)
  - Opt-out flag for DHT advertisement when running a P2P listener

### Initial features (pre-changelog)
- GPG PQC crypto wrapper (`crypto.py`): Kyber-768 + brainpoolP384r1 keygen, encrypt/decrypt, export/import
- JSON wire protocol (`protocol.py`): 17 envelope types (register, send, recv, ack, route-advertise, relay-forward, who-has, route-found, find-node, find-value, store, closer-nodes, value-found, p2p-direct, online, error)
- Embeddable relay (`relay.py`): sessions, message queue (300s TTL), federation via peer WebSockets, gossip loop
- Kademlia DHT (`dht.py`): 160-bit keyspace, K=8 buckets, α=3 lookup, FIND_NODE/FIND_VALUE/STORE RPCs, republish
- CLI (`client.py`): init, id, export, import, contacts, send, listen, chat, connect, listen-p2p, dht
- Direct P2P mode (Alice connects to Bob's embedded relay)
- Federated relays (two relays connected via `--peer`)
- Dockerfile for relay container
- README.md with topology docs, DEVELOPER.md with architecture
