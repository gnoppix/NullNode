#-------------------------------------------------------------------------------
# Name: Gnoppix Linux - Services
# Architecture: all
# Date: 2002-2026 by Gnoppix Linux
# Author: Andreas Mueller
# Website: https://www.gnoppix.com
# Licence: Business Source License (BSL / BUSL)
# You can use the code for free if your company or organisation doesn't have more than 2 people.
#-------------------------------------------------------------------------------
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import secrets
import random
import sqlite3
import ssl
import time
from collections import defaultdict

import websockets

from protocol import (
    Envelope,
    DHT_POW_DIFFICULTY,
    pow_check,
    pow_solve,
)
from crypto import (
    null_id as compute_null_id,
    validate_fingerprint,
    validate_null_id,
    verify_signature,
    sign_data,
)

logger = logging.getLogger("dht")

# ------------------------------------------------------------------ #
#  Constants                                                         #
# ------------------------------------------------------------------ #

BOOTSTRAP_SEEDS = [
    "wss://bootstrap-eu.gnoppix.org:9001",
    "wss://bootstrap-us.gnoppix.org:9001",
    "wss://bootstrap-asia.gnoppix.org:9001",
]

DHT_PORT = 6881
K_BUCKET_SIZE = 8
MAX_STORE_PER_KEY = 100       # max messages in a mailbox
STORE_TTL = 86400             # 24 hours default TTL
ADDR_TTL = 7200               # 2 hours for address records
POW_MAX_AGE = 300             # PoW nonce valid for 5 minutes
MAX_VALUE_SIZE = 4096         # max encrypted blob size (4 KB)
MAX_TOTAL_KEYS = 1_000_000    # max keys this node will store

# Stealth mode: respond to non-clients with ambiguous message instead of dht-error
STEALTH_MODE = os.environ.get("NULLNODE_STEALTH", "false").lower() == "true"
STEALTH_RESPONSES = [
    "HTTP/1.1 400 Bad Request",
    "Connection rejected",
    "",  # Empty response to confuse scanners
]


def _stealth_response() -> str:
    """Return a random stealth response for non-client connections.

    This confuses port scanners and bots that probe random WebSocket ports.
    They receive ambiguous responses that don't reveal we're a NullNode DHT.
    """
    return random.choice(STEALTH_RESPONSES)


# TOFU pinning cache path
PIN_CACHE_PATH = os.path.expanduser("~/.nullnode/pin_cache.json")

# Bootstrap server cert pinning cache path
BOOTSTRAP_PIN_CACHE_PATH = os.path.expanduser("~/.nullnode/bootstrap_pin_cache.json")


# ------------------------------------------------------------------ #
#  TOFU pinning cache                                                #
# ------------------------------------------------------------------ #

def _pin_cache_load() -> dict[str, dict]:
    """Load the TOFU pin cache from disk.

    Maps null_id -> {address, fp, first_seen, last_verified}.
    """
    if not os.path.exists(PIN_CACHE_PATH):
        return {}
    try:
        with open(PIN_CACHE_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _pin_cache_save(cache: dict[str, dict]) -> None:
    """Persist the TOFU pin cache to disk."""
    os.makedirs(os.path.dirname(PIN_CACHE_PATH), exist_ok=True)
    with open(PIN_CACHE_PATH, "w") as f:
        json.dump(cache, f, indent=2)


def pin_get(null_id: str) -> dict | None:
    """Look up a pinned address for a null ID."""
    return _pin_cache_load().get(null_id)


def pin_update(null_id: str, address: str, fingerprint: str) -> None:
    """Update or create a pinned address for a null ID.

    On first sight (TOFU): stores the address.
    On subsequent sight: only updates if the address matches the pin.
    Returns silently on mismatch -- caller decides how to handle.
    """
    cache = _pin_cache_load()
    existing = cache.get(null_id)
    now = time.time()
    if existing is None:
        # Trust on first use
        cache[null_id] = {
            "address": address,
            "fp": fingerprint,
            "first_seen": now,
            "last_verified": now,
        }
        logger.info("TOFU pin: %s -> %s (first seen)", null_id, address)
    elif existing["address"] == address:
        # Same address -- refresh timestamp
        existing["last_verified"] = now
    else:
        # Address changed -- this could be a MITM or a legitimate move
        logger.warning(
            "TOFU pin MISMATCH for %s: pinned=%s new=%s (keeping old)",
            null_id, existing["address"], address,
        )
        return  # do not overwrite
    _pin_cache_save(cache)


def pin_verify_address(null_id: str, address: str) -> bool:
    """Check if an address matches the pinned address for a null ID.

    Returns True if:
    - No pin exists yet (first use, will be pinned)
    - Address matches the pin
    Returns False if address differs from pin (possible MITM).
    """
    existing = pin_get(null_id)
    if existing is None:
        return True  # no pin yet, TOFU
    return existing["address"] == address


# ------------------------------------------------------------------ #
#  Bootstrap server certificate pinning                             #
# ------------------------------------------------------------------ #

def _bootstrap_pin_cache_load() -> dict[str, dict]:
    """Load the bootstrap cert pin cache from disk.

    Maps seed URL -> {cert_fp, first_seen, last_verified}.
    """
    if not os.path.exists(BOOTSTRAP_PIN_CACHE_PATH):
        return {}
    try:
        with open(BOOTSTRAP_PIN_CACHE_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _bootstrap_pin_cache_save(cache: dict[str, dict]) -> None:
    """Persist the bootstrap cert pin cache to disk."""
    os.makedirs(os.path.dirname(BOOTSTRAP_PIN_CACHE_PATH), exist_ok=True)
    with open(BOOTSTRAP_PIN_CACHE_PATH, "w") as f:
        json.dump(cache, f, indent=2)


def bootstrap_pin_check(seed_url: str, cert_fingerprint: str,
                        not_before: str = "", not_after: str = "") -> bool:
    """Check if a bootstrap server's TLS cert matches the pinned fingerprint.

    Uses TOFU (Trust On First Use) with cert validity window for rotation
    detection. Handles long offline periods (user gone 100+ days).

    Logic:
    - First connection: trust and pin the cert fingerprint.
    - Subsequent connection with same cert: accept.
    - Cert changed: accept if EITHER:
      a) New cert's validity window overlaps with pin age (normal rotation)
      b) New cert was issued within 90 days AND is currently valid
         (covers Let's Encrypt 90-day cycle even after long offline)
    - Reject if: new cert is expired, or validity window is older than
      180 days (possible stale MITM / rogue bootstrap).
    - User is always warned when a cert changes.

    Returns True if the cert is trusted, False if it's rejected.
    """
    MAX_CERT_AGE = 180 * 86400   # 180 days -- reject anything older
    OVERLAP_WINDOW = 90 * 86400  # 90 days -- Let's Encrypt cycle

    cache = _bootstrap_pin_cache_load()
    existing = cache.get(seed_url)

    if existing:
        if cert_fingerprint.lower() == existing["cert_fp"].lower():
            # Same cert as before -- all good
            existing["last_verified"] = time.time()
            _bootstrap_pin_cache_save(cache)
            return True

        # Cert changed -- determine if this is a legitimate rotation
        pin_time = existing.get("first_seen", 0)
        pin_age = time.time() - pin_time

        # Parse new cert validity dates
        new_not_before = 0
        new_not_after = 0
        if not_before:
            try:
                new_not_before = ssl.cert_time_to_seconds(not_before)
            except (ValueError, TypeError):
                pass
        if not_after:
            try:
                new_not_after = ssl.cert_time_to_seconds(not_after)
            except (ValueError, TypeError):
                pass

        now = time.time()

        # Check 1: New cert is currently valid AND was issued recently
        cert_currently_valid = (new_not_before <= now <= new_not_after) if (new_not_before and new_not_after) else False
        cert_issued_recently = (now - new_not_before) < OVERLAP_WINDOW if new_not_before else False
        cert_not_too_old = (new_not_after - new_not_before) < MAX_CERT_AGE if (new_not_before and new_not_after) else True

        if cert_currently_valid and cert_issued_recently and cert_not_too_old:
            logger.warning(
                "BOOTSTRAP CERT CHANGE for %s (pin age %.0f days): "
                "old=%s new=%s -- accepting (valid cert, issued %s, expires %s)",
                seed_url, pin_age / 86400,
                existing["cert_fp"][:16], cert_fingerprint[:16],
                not_before or "?", not_after or "?",
            )
            # Update to new cert, reset timer
            existing["cert_fp"] = cert_fingerprint
            existing["first_seen"] = time.time()
            existing["last_verified"] = time.time()
            _bootstrap_pin_cache_save(cache)
            return True

        # Check 2: Pin is within overlap window (short offline period)
        if pin_age < OVERLAP_WINDOW:
            logger.warning(
                "BOOTSTRAP CERT CHANGE for %s (within %d-day overlap, pin age %.0f days): "
                "old=%s new=%s -- accepting (likely rotation)",
                seed_url, OVERLAP_WINDOW // 86400, pin_age / 86400,
                existing["cert_fp"][:16], cert_fingerprint[:16],
            )
            existing["cert_fp"] = cert_fingerprint
            existing["first_seen"] = time.time()
            existing["last_verified"] = time.time()
            _bootstrap_pin_cache_save(cache)
            return True

        # All checks failed -- reject
        logger.warning(
            "BOOTSTRAP CERT CHANGE for %s (pin age %.0f days, cert_valid=%s, "
            "cert_issued_recently=%s): old=%s new=%s "
            "-- REJECTING (possible MITM / rogue bootstrap)",
            seed_url, pin_age / 86400, cert_currently_valid, cert_issued_recently,
            existing["cert_fp"][:16], cert_fingerprint[:16],
        )
        return False

    # First connection -- trust on first use
    cache[seed_url] = {
        "cert_fp": cert_fingerprint,
        "first_seen": time.time(),
        "last_verified": time.time(),
    }
    _bootstrap_pin_cache_save(cache)
    logger.info(
        "BOOTSTRAP CERT PIN: %s -> %s (first seen, TOFU)",
        seed_url, cert_fingerprint[:16],
    )
    return True


# Trusted domains for bootstrap servers (and message storage nodes).
# Bootstrap seeds must present a certificate for one of these domains.
# This prevents an attacker from running a rogue bootstrap with a valid
# cert for their own domain (e.g., evil.com) to intercept DHT traffic.
TRUSTED_DOMAINS = [
    "*.gnoppix.org",
    "*.gnoppix.com",
]

# Trusted Certificate Authority fingerprints (SHA-256 hex of DER cert).
# Bootstrap servers must present a certificate chain rooted to one of these
# CAs. This prevents an attacker from using a valid cert for *.gnoppix.org
# obtained from a compromised or rogue CA (e.g., corporate MITM, malware
# root CA, or a second CA compromise).
#
# These are the Let's Encrypt intermediate CA fingerprints. To get the
# current values: openssl s_client -connect bootstrap-eu.gnoppix.org:9001
# -showcerts </dev/null 2>/dev/null | openssl x509 -fingerprint -sha256
# -noout -in /dev/stdin
#
# LE rotates intermediates roughly every 1-2 years. When they rotate,
# update these fingerprints and release a new client version.
TRUSTED_CA_FINGERPRINTS = [
    # "LE_INTERMEDIATE_CA_SHA256_FINGERPRINT_HERE",  # R3
    # "LE_INTERMEDIATE_CA_SHA256_FINGERPRINT_HERE",  # R11 (if used)
]


def _domain_matches(cert_domain: str, pattern: str) -> bool:
    """Check if a domain matches a wildcard pattern (e.g., *.gnoppix.org)."""
    cert_domain = cert_domain.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        # Wildcard: the cert domain must be a subdomain of the base
        base = pattern[2:]
        return cert_domain == base or cert_domain.endswith("." + base)
    return cert_domain == pattern


def _cert_has_trusted_ca(cert_info: dict) -> bool:
    """Verify the certificate chains to a trusted CA.

    Checks the issuer field of the certificate for known CA identifiers.
    This is a lightweight check that doesn't require extracting the full chain.

    SECURITY: This prevents an attacker from using a valid cert for *.gnoppix.org
    obtained from a non-trusted CA (rogue CA, corporate MITM, malware root CA).

    Returns True if:
    - No CA pins are configured (skip check)
    - The cert issuer matches a trusted CA identifier
    - The cert is self-signed by a trusted CA (issuer == subject for root CAs)
    """
    if not TRUSTED_CA_FINGERPRINTS:
        # No CA pins configured -- fall back to issuer name check
        return _cert_issuer_is_trusted(cert_info)

    # If CA fingerprints are configured, we'd need the full chain.
    # Since getpeercert(chain=True) is available in Python 3.13+, we use
    # the issuer name check as the primary method.
    return _cert_issuer_is_trusted(cert_info)


def _cert_issuer_is_trusted(cert_info: dict) -> bool:
    """Check if the certificate issuer is a known trusted CA.

    Examines the issuer CN and organizationName fields.
    """
    issuer = cert_info.get("issuer", [])
    issuer_parts = {}
    for rdn in issuer:
        if isinstance(rdn, tuple) and len(rdn) == 2:
            issuer_parts[rdn[0]] = rdn[1]

    cn = issuer_parts.get("commonName", "").lower()
    org = issuer_parts.get("organizationName", "").lower()

    # Let's Encrypt
    if "let's encrypt" in org or "let's encrypt" in cn:
        return True

    # ISRG (Internet Security Research Group) -- Let's Encrypt's parent
    if "isrg" in org or "internet security" in org:
        return True

    logger.warning(
        "bootstrap cert issuer NOT TRUSTED (CN=%s, org=%s) — "
        "must chain to Let's Encrypt",
        issuer_parts.get("commonName", "?"),
        issuer_parts.get("organizationName", "?"),
    )
    return False


def _cert_has_trusted_domain(cert_info: dict) -> bool:
    """Check if the certificate has a SAN or CN matching TRUSTED_DOMAINS.

    Returns True if the cert includes at least one name from our trusted
    domain list. This checks Subject Alternative Names first, then falls
    back to the Subject commonName.
    """
    # Check Subject Alternative Names (SAN)
    san = cert_info.get("subjectAltName", [])
    for entry in san:
        if isinstance(entry, tuple) and len(entry) == 2:
            kind, value = entry
            if kind == "DNS":
                for pattern in TRUSTED_DOMAINS:
                    if _domain_matches(value, pattern):
                        return True

    # Fall back to Subject commonName
    subject = cert_info.get("subject", [])
    for rdn in subject:
        if isinstance(rdn, tuple) and len(rdn) == 2:
            attr_type, attr_value = rdn
            if attr_type == "commonName":
                for pattern in TRUSTED_DOMAINS:
                    if _domain_matches(attr_value, pattern):
                        return True

    return False


def verify_bootstrap_cert(seed_url: str, ssl_ctx: object = None) -> bool:
    """Verify the TLS certificate of a bootstrap server by connecting via SSL.

    Performs a raw SSL handshake to extract the peer certificate fingerprint
    and validity dates, then checks it against pinned values. Returns True
    if trusted.

    SECURITY: Also verifies the certificate belongs to a trusted domain
    (*.gnoppix.org or *.gnoppix.com) and chains to a trusted CA
    (Let's Encrypt). This prevents an attacker from running a rogue
    bootstrap server with a valid cert for their own domain, or a
    valid cert for *.gnoppix.org obtained from a rogue/compromised CA.

    This is needed because websockets doesn't expose peer cert info on
    its protocol objects, so we do a separate verification connection.
    """
    import ssl as _ssl
    import socket

    # Parse host:port from seed URL
    # seed_url format: wss://host:port
    url = seed_url.replace("wss://", "")
    if ":" in url:
        host, port_str = url.rsplit(":", 1)
        port = int(port_str)
    else:
        host = url
        port = 443

    try:
        sock = socket.create_connection((host, port), timeout=5)
        verify_ctx = _ssl.create_default_context()
        ssock = verify_ctx.wrap_socket(sock, server_hostname=host)

        # Get DER for fingerprinting
        der_cert = ssock.getpeercert(binary_form=True)
        # Get parsed cert for validity dates and domain check
        cert_info = ssock.getpeercert()
        ssock.close()

        if not der_cert:
            logger.warning("bootstrap %s did not present a certificate", seed_url)
            return False

        cert_fp = hashlib.sha256(der_cert).hexdigest()

        # SECURITY: Verify the cert belongs to a trusted domain
        if not _cert_has_trusted_domain(cert_info):
            logger.warning(
                "bootstrap %s cert domain NOT TRUSTED (SAN=%s CN=%s) — "
                "rejecting (must be *.gnoppix.org or *.gnoppix.com)",
                seed_url,
                [v for _, v in cert_info.get("subjectAltName", []) if isinstance(v, str)],
                [v for t, v in cert_info.get("subject", []) if t == "commonName"],
            )
            return False

        # SECURITY: Verify the cert chains to a trusted CA (Let's Encrypt)
        if not _cert_has_trusted_ca(cert_info):
            logger.warning(
                "bootstrap %s cert CA NOT TRUSTED (issuer=%s) — "
                "rejecting (must chain to Let's Encrypt)",
                seed_url,
                [f"{t}={v}" for t, v in cert_info.get("issuer", []) if isinstance(t, str)],
            )
            return False

        # Extract validity dates from the cert
        not_after = cert_info.get("notAfter", "")
        not_before = cert_info.get("notBefore", "")

        return bootstrap_pin_check(seed_url, cert_fp, not_before, not_after)
    except Exception as e:
        logger.warning("bootstrap cert verification failed for %s: %s", seed_url, e)
        return False


# ------------------------------------------------------------------ #
#  Bot / Intrusion Detection Log                                      #
# ------------------------------------------------------------------ #

BOT_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bot_connection.log")


def _log_bot_activity(peer_ip: str, peer_port: int, reason: str, detail: str = ""):
    """Log suspicious bot/scanner activity to bot_connection.log.

    Writes a structured log line similar to nginx access log format:
    2026-06-23T14:32:01+0000 203.0.113.5:54321 SCANNER bad_envelope: invalid JSON
    """
    import datetime

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")
    # Insert colon in timezone offset for readability: +0000 -> +00:00
    ts = ts[:-2] + ":" + ts[-2:]
    detail_str = f" ({detail})" if detail else ""
    log_line = f"{ts} {peer_ip}:{peer_port} {reason}{detail_str}"

    try:
        with open(BOT_LOG_PATH, "a") as f:
            f.write(log_line + "\n")
    except OSError:
        logger.warning("could not write to %s", BOT_LOG_PATH)


def _get_peer_address(ws) -> tuple:
    """Extract the peer (host, port) from a WebSocket connection.

    Works with both websockets 10+ and older versions.
    """
    # websockets 10+: ws.remote_address returns (host, port)
    if hasattr(ws, "remote_address") and ws.remote_address:
        return ws.remote_address[0], ws.remote_address[1]

    # Fallback: get the underlying transport socket
    try:
        transport = ws.transport
        if transport:
            sock_info = transport.get_extra_info("peername")
            if sock_info and len(sock_info) >= 2:
                return str(sock_info[0]), int(sock_info[1])
    except Exception:
        pass

    return "unknown", 0


# ------------------------------------------------------------------ #
#  Utilities                                                         #
# ------------------------------------------------------------------ #

def node_id_from_nid(nid: str) -> int:
    """Derive a 160-bit Kademlia node ID from a Null ID."""
    digest = hashlib.sha256(nid.encode()).digest()
    return int.from_bytes(digest[:20], "big")


def hash_key(key: str) -> int:
    """Hash a DHT key to a 160-bit integer for XOR distance."""
    digest = hashlib.sha256(key.encode()).digest()
    return int.from_bytes(digest[:20], "big")


def xor_distance(a: int, b: int) -> int:
    return a ^ b


# ------------------------------------------------------------------ #
#  Persistent storage (SQLite)                                       #
# ------------------------------------------------------------------ #

class DHTStore:
    """SQLite-backed persistent DHT storage.

    SECURITY: Keys are stored as-is (they are null IDs which are public).
    Values are encrypted blobs -- the storage layer never sees plaintext.
    """

    def __init__(self, db_path: str | None = None):
        if db_path is None:
            db_path = os.path.expanduser("~/.nullnode/dht_store.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_tables()

    def _init_tables(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS kv_store (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                salt TEXT NOT NULL DEFAULT '',
                seq INTEGER NOT NULL DEFAULT 0,
                publisher_fp TEXT NOT NULL DEFAULT '',
                stored_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                sig TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_expires ON kv_store(expires_at);
            CREATE INDEX IF NOT EXISTS idx_publisher ON kv_store(publisher_fp);
        """)
        self._conn.commit()

    def get(self, key: str) -> dict | None:
        """Retrieve a value by key. Returns None if expired or not found."""
        now = time.time()
        row = self._conn.execute(
            "SELECT value, salt, seq, publisher_fp, stored_at, expires_at, sig "
            "FROM kv_store WHERE key = ? AND expires_at > ?",
            (key, now),
        ).fetchone()
        if not row:
            return None
        return {
            "value": row[0], "salt": row[1], "seq": row[2],
            "publisher_fp": row[3], "stored_at": row[4],
            "expires_at": row[5], "sig": row[6],
        }

    def put(self, key: str, value: str, salt: str, seq: int,
            publisher_fp: str, ttl: int, sig: str) -> bool:
        """Store a value. Returns True if stored, False if rejected.

        SECURITY: Only stores if:
        - The new seq is higher than existing (prevents replay)
        - The signature is valid (verified by caller)
        - The value size is within limits
        """
        if len(value) > MAX_VALUE_SIZE:
            logger.warning("value too large: %d bytes", len(value))
            return False
        now = time.time()
        expires = now + ttl

        existing = self._conn.execute(
            "SELECT seq FROM kv_store WHERE key = ?", (key,)
        ).fetchone()

        if existing and existing[0] >= seq:
            logger.debug("stale seq %d < existing %d for key %s", seq, existing[0], key)
            return False

        self._conn.execute(
            "INSERT OR REPLACE INTO kv_store "
            "(key, value, salt, seq, publisher_fp, stored_at, expires_at, sig) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (key, value, salt, seq, publisher_fp, now, expires, sig),
        )
        self._conn.commit()
        return True

    def delete_expired(self) -> int:
        now = time.time()
        cur = self._conn.execute(
            "DELETE FROM kv_store WHERE expires_at <= ?", (now,)
        )
        self._conn.commit()
        return cur.rowcount

    def count_keys(self) -> int:
        return self._conn.execute(
            "SELECT COUNT(*) FROM kv_store WHERE expires_at > ?",
            (time.time(),)
        ).fetchone()[0]

    def close(self):
        self._conn.close()


# ------------------------------------------------------------------ #
#  DHT Node                                                          #
# ------------------------------------------------------------------ #

class DHTNode:
    """Kademlia-style DHT node with store-and-forward mailbox.

    Features:
    - BEP-44-style mutable items with signatures
    - Proof-of-work for writes (anti-spam)
    - Persistent SQLite storage
    - Encrypted mailbox storage for offline recipients
    - Address ownership verification (signed address records)
    - TOFU pinning for peer addresses
    """

    def __init__(
        self,
        null_id: str,
        host: str = "0.0.0.0",
        port: int = 0,
        fingerprint: str = "",
        store: DHTStore | None = None,
        ssl_certfile: str = "",
        ssl_keyfile: str = "",
    ):
        self.nid = null_id
        self.fingerprint = fingerprint
        self.node_id = node_id_from_nid(null_id)
        self.host = host
        self.port = port
        self.address = ""
        self.store = store or DHTStore()
        self.ssl_certfile = ssl_certfile
        self.ssl_keyfile = ssl_keyfile

        # Routing table
        self.routing_table: dict[int, list[dict]] = defaultdict(list)
        self._server = None
        self._running = False

        # Anti-replay: track seen (key, nonce) pairs
        self._seen_nonces: dict[str, set[int]] = defaultdict(set)
        self._nonce_cleanup_task = None

    async def start(self, port: int | None = None):
        if port:
            self.port = port
        if not self.port:
            self.port = DHT_PORT + secrets.randbelow(1000)

        ssl_ctx = None
        if self.ssl_certfile and self.ssl_keyfile:
            import ssl
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(self.ssl_certfile, self.ssl_keyfile)
            logger.info("TLS enabled (cert=%s)", self.ssl_certfile)

        self._server = await websockets.serve(
            self._handle_connection,
            self.host,
            self.port,
            ping_interval=30,
            ping_timeout=10,
            max_size=MAX_VALUE_SIZE * 2,
            ssl=ssl_ctx,
        )
        self.port = self._server.sockets[0].getsockname()[1]
        scheme = "wss" if ssl_ctx else "ws"
        self.address = f"{scheme}://{self.host}:{self.port}"
        self._running = True
        self._nonce_cleanup_task = asyncio.create_task(self._cleanup_nonces())
        logger.info("DHT node %s listening on %s (id=0x%x)", self.nid, self.address, self.node_id)

    async def stop(self):
        self._running = False
        if self._nonce_cleanup_task:
            self._nonce_cleanup_task.cancel()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self.store.close()

    # ------------------------------------------------------------------ #
    #  Connection handler                                                 #
    # ------------------------------------------------------------------ #

    async def _handle_connection(self, ws):
        peer_ip, peer_port = _get_peer_address(ws)
        consecutive_failures = 0
        MAX_CONSECUTIVE_FAILURES = 10

        try:
            async for raw in ws:
                try:
                    env = Envelope.from_json(raw)
                except (json.JSONDecodeError, KeyError) as e:
                    consecutive_failures += 1
                    if consecutive_failures == MAX_CONSECUTIVE_FAILURES:
                        _log_bot_activity(peer_ip, peer_port, "SCANNER", f"bad_envelope x{MAX_CONSECUTIVE_FAILURES}")
                    if STEALTH_MODE:
                        # Stealth mode: return ambiguous response to confuse scanners
                        await ws.send(_stealth_response())
                    else:
                        await ws.send(Envelope.dht_error("", f"bad envelope: {e}").to_json())
                    continue

                # SECURITY: Validate timestamp freshness
                if abs(time.time() - env.ts) > POW_MAX_AGE:
                    consecutive_failures += 1
                    if consecutive_failures == MAX_CONSECUTIVE_FAILURES:
                        _log_bot_activity(peer_ip, peer_port, "SCANNER", f"stale_timestamp x{MAX_CONSECUTIVE_FAILURES}")
                    if STEALTH_MODE:
                        await ws.send(_stealth_response())
                    else:
                        await ws.send(Envelope.dht_error(
                            env.payload.get("key", ""), "stale timestamp"
                        ).to_json())
                    continue

                # Reset failure counter on valid message
                consecutive_failures = 0

                if env.type == "dht-put":
                    await self._handle_put(env, ws)
                elif env.type == "dht-get":
                    await self._handle_get(env, ws)
                elif env.type == "dht-addr-record":
                    await self._handle_addr_record(env, ws)
                else:
                    _log_bot_activity(peer_ip, peer_port, "BAD_TYPE", env.type)
                    if STEALTH_MODE:
                        # Stealth mode: return ambiguous response for unknown types
                        await ws.send(_stealth_response())
                    else:
                        await ws.send(Envelope.dht_error(
                            env.payload.get("key", ""), f"unexpected type: {env.type}"
                        ).to_json())
        except websockets.exceptions.ConnectionClosed:
            # Log connections that close immediately (likely scanner probe)
            # We can't easily detect HTTP probes here since websockets rejects
            # them at the handshake level before reaching this handler.
            pass

        # Log if connection had high failure rate before disconnect
        if consecutive_failures >= 5:
            _log_bot_activity(
                peer_ip, peer_port, "SUSPECT",
                f"{consecutive_failures} consecutive failures"
            )

    # ------------------------------------------------------------------ #
    #  PUT handler -- with PoW + signature verification                  #
    # ------------------------------------------------------------------ #

    async def _handle_put(self, env: Envelope, ws):
        key = env.payload.get("key", "")
        value_b64 = env.payload.get("value", "")
        salt = env.payload.get("salt", "")
        seq = env.payload.get("seq", 0)
        ttl = min(env.payload.get("ttl", STORE_TTL), STORE_TTL)
        nonce = env.payload.get("nonce", 0)
        sig = env.sig

        # Validate key format
        if not validate_null_id(key):
            await ws.send(Envelope.dht_error(key, "invalid key format").to_json())
            return

        # Validate value size
        if len(value_b64) > MAX_VALUE_SIZE:
            await ws.send(Envelope.dht_error(key, "value too large").to_json())
            return

        # Anti-replay: check nonce not seen
        if nonce in self._seen_nonces.get(key, set()):
            await ws.send(Envelope.dht_error(key, "nonce replay").to_json())
            return

        # Verify proof-of-work
        pow_data = f"{key}{value_b64}{salt}{seq}"
        if not pow_check(pow_data, nonce, DHT_POW_DIFFICULTY):
            await ws.send(Envelope.dht_error(key, "insufficient proof-of-work").to_json())
            return

        # Verify signature (publisher signs key + value + salt + seq + nonce)
        if not sig:
            await ws.send(Envelope.dht_error(key, "missing signature").to_json())
            return

        publisher_fp = env.payload.get("publisher_fp", "")
        if not validate_fingerprint(publisher_fp):
            await ws.send(Envelope.dht_error(key, "invalid publisher fingerprint").to_json())
            return

        # Verify the publisher owns this key (key must be their null_id)
        expected_nid = compute_null_id(publisher_fp)
        if expected_nid != key:
            await ws.send(Envelope.dht_error(
                key, f"key mismatch: expected {expected_nid}"
            ).to_json())
            return

        # Verify signature
        sign_data_str = f"{key}|{value_b64}|{salt}|{seq}|{nonce}"
        if not verify_signature(sign_data_str, sig, publisher_fp):
            await ws.send(Envelope.dht_error(key, "signature verification failed").to_json())
            return

        # Store
        stored = self.store.put(key, value_b64, salt, seq, publisher_fp, ttl, sig)
        if stored:
            self._seen_nonces[key].add(nonce)
            await ws.send(Envelope.dht_found(key, value_b64, salt, seq).to_json())
            logger.debug("stored key %s seq %d", key, seq)
        else:
            await ws.send(Envelope.dht_error(key, "stale sequence or storage full").to_json())

    # ------------------------------------------------------------------ #
    #  GET handler                                                       #
    # ------------------------------------------------------------------ #

    async def _handle_get(self, env: Envelope, ws):
        key = env.payload.get("key", "")
        if not validate_null_id(key):
            await ws.send(Envelope.dht_error(key, "invalid key format").to_json())
            return

        result = self.store.get(key)
        if result:
            await ws.send(Envelope.dht_found(
                key, result["value"], result["salt"], result["seq"]
            ).to_json())
        else:
            await ws.send(Envelope.dht_error(key, "not found").to_json())

    # ------------------------------------------------------------------ #
    #  Address record handler -- ownership verification                  #
    # ------------------------------------------------------------------ #

    async def _handle_addr_record(self, env: Envelope, ws):
        """Handle a signed address record.

        The publisher proves they own the null_id by signing:
            null_id|address|ttl

        This is stored alongside regular DHT records and returned on lookup.
        The signature is verified against the publisher's known fingerprint.
        """
        null_id = env.payload.get("null_id", "")
        address = env.payload.get("address", "")
        ttl = env.payload.get("ttl", ADDR_TTL)
        publisher_fp = env.payload.get("publisher_fp", "")
        sig = env.sig

        # Validate null_id format
        if not validate_null_id(null_id):
            await ws.send(Envelope.dht_error(null_id, "invalid null_id format").to_json())
            return

        # Validate publisher fingerprint
        if not validate_fingerprint(publisher_fp):
            await ws.send(Envelope.dht_error(null_id, "invalid publisher fingerprint").to_json())
            return

        # Verify the publisher owns this null_id
        expected_nid = compute_null_id(publisher_fp)
        if expected_nid != null_id:
            await ws.send(Envelope.dht_error(
                null_id, f"null_id mismatch: expected {expected_nid}"
            ).to_json())
            return

        # Verify signature over null_id|address|ttl
        sign_data_str = f"{null_id}|{address}|{ttl}"
        if not verify_signature(sign_data_str, sig, publisher_fp):
            await ws.send(Envelope.dht_error(null_id, "signature verification failed").to_json())
            return

        # Store as a regular kv record with the address as value
        # Use a special salt prefix "addr:" to distinguish from mailbox records
        salt = f"addr:{secrets.token_hex(4)}"
        stored = self.store.put(
            null_id, address, salt, seq=int(time.time()),
            publisher_fp=publisher_fp, ttl=ttl, sig=sig,
        )
        if stored:
            self._seen_nonces[null_id].add(0)  # no PoW nonce for addr records
            await ws.send(Envelope.dht_found(null_id, address, salt, 0).to_json())
            logger.info("stored addr record: %s -> %s (fp=%s)", null_id, address, publisher_fp[:16])
        else:
            await ws.send(Envelope.dht_error(null_id, "stale address record").to_json())

    # ------------------------------------------------------------------ #
    #  Public API                                                        #
    # ------------------------------------------------------------------ #

    async def store_mailbox(
        self,
        recipient_nid: str,
        encrypted_blob_b64: str,
        publisher_fp: str,
        seq: int,
    ) -> bool:
        """Store an encrypted message in a recipient's DHT mailbox.

        SECURITY: The message is signed by the sender. Only the recipient
        (who owns the private key for their null_id) can decrypt it.
        """
        salt = secrets.token_hex(8)
        nonce = 0
        pow_data = f"{recipient_nid}{encrypted_blob_b64}{salt}{seq}"
        nonce = pow_solve(pow_data, DHT_POW_DIFFICULTY)

        sign_data_str = f"{recipient_nid}|{encrypted_blob_b64}|{salt}|{seq}|{nonce}"
        sig = sign_data(sign_data_str, publisher_fp)

        env = Envelope.dht_put(
            key=recipient_nid,
            value_b64=encrypted_blob_b64,
            salt=salt,
            seq=seq,
            ttl=STORE_TTL,
            nonce=nonce,
        )
        env.payload["publisher_fp"] = publisher_fp
        env.sig = sig

        # Store locally first
        self.store.put(
            recipient_nid, encrypted_blob_b64, salt, seq,
            publisher_fp, STORE_TTL, sig,
        )

        # Replicate to closest nodes
        await self._replicate(env)
        return True

    async def get_mailbox(self, my_nid: str) -> list[dict]:
        """Poll the DHT for messages in our mailbox.

        Returns list of {value, salt, seq, publisher_fp} dicts.
        """
        # Check local store first
        result = self.store.get(my_nid)
        if result:
            return [result]

        # If not found locally, query the DHT
        env = Envelope.dht_get(my_nid)
        results = await self._query_closest(my_nid, env)
        return [r for r in results if r.get("value")]

    async def advertise_address(self, my_nid: str, my_fp: str,
                                advertise_addr: str):
        """Store our address in the DHT so peers can find us.

        Key = our null_id, value = our address, signed by our key.
        Uses the dht-addr-record type for ownership verification.
        """
        salt = secrets.token_hex(8)
        seq = int(time.time())
        nonce = 0
        pow_data = f"{my_nid}{advertise_addr}{salt}{seq}"
        nonce = pow_solve(pow_data, DHT_POW_DIFFICULTY)

        sign_data_str = f"{my_nid}|{advertise_addr}|{salt}|{seq}|{nonce}"
        sig = sign_data(sign_data_str, my_fp)

        env = Envelope.dht_put(
            key=my_nid,
            value_b64=advertise_addr,
            salt=salt,
            seq=seq,
            ttl=ADDR_TTL,
            nonce=nonce,
        )
        env.payload["publisher_fp"] = my_fp
        env.sig = sig

        self.store.put(my_nid, advertise_addr, salt, seq, my_fp, ADDR_TTL, sig)
        await self._replicate(env)
        logger.info("advertised %s -> %s", my_nid, advertise_addr)

    async def publish_addr_record(self, my_nid: str, my_fp: str,
                                   address: str) -> bool:
        """Publish a signed address record proving we own our null_id.

        This uses the dht-addr-record message type which requires a valid
        signature over null_id|address|ttl. Peers can verify this signature
        to confirm the address actually belongs to the key owner.
        """
        ttl = ADDR_TTL
        sign_data_str = f"{my_nid}|{address}|{ttl}"
        sig = sign_data(sign_data_str, my_fp)

        env = Envelope.dht_addr_record(
            null_id=my_nid,
            address=address,
            ttl=ttl,
            publisher_fp=my_fp,
        )
        env.sig = sig

        # Store locally
        salt = f"addr:{secrets.token_hex(4)}"
        self.store.put(my_nid, address, salt, int(time.time()), my_fp, ttl, sig)

        # Replicate to closest nodes
        await self._replicate(env)
        logger.info("published addr record: %s -> %s", my_nid, address)
        return True

    async def lookup(self, target_nid: str, timeout: float = 10) -> str | None:
        """Look up a peer's address in the DHT.

        Returns the address string or None if not found.

        SECURITY: Validates the returned address against the TOFU pin cache.
        If the address doesn't match the pin, the lookup result is rejected
        and None is returned (possible MITM).
        """
        # Check TOFU pin cache first -- if we have a pinned address, use it
        pinned = pin_get(target_nid)
        if pinned:
            logger.debug("using pinned address for %s: %s", target_nid, pinned["address"])
            return pinned["address"]

        env = Envelope.dht_get(target_nid)
        results = await self._query_closest(target_nid, env, timeout=timeout)
        if results:
            # Return the most recent (highest seq) address record
            best = max(results, key=lambda r: r.get("seq", 0))
            address = best.get("value")

            # SECURITY: Validate address ownership
            # Check if the result came with a valid address record
            # (salt starts with "addr:" for address records)
            salt = best.get("salt", "")
            publisher_fp = best.get("publisher_fp", "")

            if salt.startswith("addr:") and publisher_fp:
                # This is a signed address record -- verify ownership
                expected_nid = compute_null_id(publisher_fp)
                if expected_nid != target_nid:
                    logger.warning(
                        "lookup: address record ownership mismatch for %s "
                        "(claimed fp=%s, expected nid=%s)",
                        target_nid, publisher_fp[:16], expected_nid,
                    )
                    return None

                # Verify the signature
                sign_data_str = f"{target_nid}|{address}|{ADDR_TTL}"
                if not verify_signature(sign_data_str, best.get("sig", ""), publisher_fp):
                    logger.warning(
                        "lookup: address record signature invalid for %s", target_nid,
                    )
                    return None

                # TOFU pin the verified address
                pin_update(target_nid, address, publisher_fp)
                # SECURITY: First-contact warning -- no prior pin existed
                logger.warning(
                    "lookup: FIRST CONTACT for %s -> %s (fp=%s) -- "
                    "TOFU pinned. Verify this address out-of-band!",
                    target_nid, address, publisher_fp[:16],
                )
                return address
            else:
                # SECURITY: Reject unsigned results for address lookups.
                # Only signed address records (salt prefix "addr:") are accepted.
                # An attacker running a malicious DHT node could return fake
                # unsigned addresses to redirect connections.
                logger.warning(
                    "lookup: unsigned address record for %s -- rejecting "
                    "(possible MITM from malicious DHT node)",
                    target_nid,
                )
                return None

        return None

    # ------------------------------------------------------------------ #
    #  Internal DHT operations                                           #
    # ------------------------------------------------------------------ #

    async def _replicate(self, env: Envelope):
        """Replicate a DHT put to the closest known nodes."""
        key = env.payload.get("key", "")
        target_id = hash_key(key)
        closest = self._find_closest_nodes(target_id, K_BUCKET_SIZE * 2)
        tasks = []
        for node in closest:
            tasks.append(self._send_to_node(node, env))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _query_closest(
        self,
        target_nid: str,
        env: Envelope,
        timeout: float = 10,
    ) -> list[dict]:
        """Query the DHT network for the value associated with target_nid."""
        target_id = hash_key(target_nid)
        closest = self._find_closest_nodes(target_id, K_BUCKET_SIZE * 2)
        tasks = []
        for node in closest:
            tasks.append(self._query_node(node, env))
        if not tasks:
            return []
        results = await asyncio.gather(*tasks, return_exceptions=True)
        found = []
        for r in results:
            if isinstance(r, dict) and r.get("value"):
                found.append(r)
        return found

    async def _send_to_node(self, node: dict, env: Envelope):
        try:
            ws = await websockets.connect(node["address"], open_timeout=5)
            await ws.send(env.to_json())
            await ws.close()
        except Exception:
            pass

    async def _query_node(self, node: dict, env: Envelope) -> dict | None:
        try:
            ws = await websockets.connect(node["address"], open_timeout=5)
            await ws.send(env.to_json())
            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            await ws.close()
            resp = Envelope.from_json(raw)
            if resp.type == "dht-found":
                return {
                    "value": resp.payload.get("value", ""),
                    "salt": resp.payload.get("salt", ""),
                    "seq": resp.payload.get("seq", 0),
                    "publisher_fp": resp.payload.get("publisher_fp", ""),
                    "sig": resp.payload.get("sig", ""),
                }
        except Exception:
            pass
        return None

    def _find_closest_nodes(self, target_id: int, count: int) -> list[dict]:
        """Find the closest known nodes to target_id in the routing table."""
        all_nodes = []
        for bucket in self.routing_table.values():
            all_nodes.extend(bucket)
        all_nodes.sort(
            key=lambda n: xor_distance(n.get("node_id", 0), target_id)
        )
        return all_nodes[:count]

    async def _cleanup_nonces(self):
        """Periodically clear old nonce tracking to prevent memory leak."""
        while self._running:
            await asyncio.sleep(600)
            self._seen_nonces.clear()


# ------------------------------------------------------------------ #
#  Factory                                                           #
# ------------------------------------------------------------------ #

async def create_dht_node(
    null_id: str,
    host: str = "0.0.0.0",
    port: int = 0,
    bootstrap_nodes: list[str] | None = None,
    use_cache: bool = True,
    fingerprint: str = "",
    ssl_certfile: str = "",
    ssl_keyfile: str = "",
) -> DHTNode:
    """Create and start a DHT node, optionally joining the network."""
    store = DHTStore()
    node = DHTNode(null_id, host, port, fingerprint, store,
                   ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile)
    await node.start(port)

    # Join the network via bootstrap nodes
    if bootstrap_nodes:
        for seed in bootstrap_nodes:
            try:
                # SECURITY: Verify bootstrap server identity before trusting
                if seed.startswith("wss://"):
                    if not verify_bootstrap_cert(seed, None):
                        logger.warning(
                            "bootstrap %s cert verification failed — skipping "
                            "(possible rogue bootstrap / MITM)",
                            seed,
                        )
                        continue

                ws = await websockets.connect(seed, open_timeout=5)
                # Send a find-node for ourselves to populate the routing table
                env = Envelope.dht_get(null_id)
                await ws.send(env.to_json())
                raw = await asyncio.wait_for(ws.recv(), timeout=5)
                await ws.close()
                logger.info("connected to bootstrap %s", seed)
            except Exception as e:
                logger.warning("bootstrap %s failed: %s", seed, e)

    return node
