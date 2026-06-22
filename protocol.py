#-------------------------------------------------------------------------------
# Name: Gnoppix Linux - Services
# Architecture: all
# Date: 2002-2006 by Gnoppix Linux
# Author: Andreas Mueller
# Website: https://www.gnoppix.com
# Licence: Business Source License (BSL / BUSL)
#-------------------------------------------------------------------------------
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Literal

# ------------------------------------------------------------------ #
#  Message types                                                     #
# ------------------------------------------------------------------ #

MessageType = Literal[
    # DHT store-and-forward (mailbox)
    "dht-put",          # Store an encrypted blob in the DHT
    "dht-get",          # Retrieve a blob by key
    "dht-found",        # Response: blob found
    "dht-error",        # DHT operation failed
    "dht-addr-record",  # Signed address record (proves ownership of a DHT key)

    # Direct P2P session
    "p2p-hello",        # Handshake: public key + proof-of-work
    "p2p-hello-ack",   # Handshake accepted
    "p2p-message",      # Encrypted message with sequence number
    "p2p-ack",          # Delivery confirmation
    "p2p-ping",         # Keep-alive
    "p2p-pong",         # Keep-alive response

    # NAT traversal
    "nat-punch",        # Hole-punching coordination
    "nat-punch-ack",    # Hole-punching acknowledged

    # Legacy relay (fallback only — Phase 2 deprecation)
    "register",
    "registered",
    "send",
    "recv",
    "ack",
    "error",
    "online",
    "offline",
    "relay-forward",
    "route-advertise",
    "who-has",
    "route-found",
    "peer-auth",
    "peer-auth-reply",
]

# ------------------------------------------------------------------ #
#  Proof-of-work difficulty (leading zero bits)                      #
# ------------------------------------------------------------------ #

# DHT writes require PoW to prevent spam.
# Difficulty 16 = ~0.5s on modern CPU, ~65k hash attempts
DHT_POW_DIFFICULTY = 16

# P2P hello requires lighter PoW (anti-spam for connection initiation)
# Difficulty 12 = ~0.1s on modern CPU
P2P_POW_DIFFICULTY = 12


# ------------------------------------------------------------------ #
#  Envelope                                                          #
# ------------------------------------------------------------------ #

@dataclass
class Envelope:
    type: MessageType
    payload: dict = field(default_factory=dict)
    msg_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    ts: float = field(default_factory=time.time)
    sig: str = ""       # base64-encoded detached GPG signature

    def to_json(self) -> str:
        return json.dumps({
            "type": self.type,
            "payload": self.payload,
            "msg_id": self.msg_id,
            "ts": self.ts,
            "sig": self.sig,
        })

    @classmethod
    def from_json(cls, raw: str) -> "Envelope":
        d = json.loads(raw)
        return cls(**d)

    def signing_payload(self) -> str:
        """Canonical JSON for signing/verification (excludes sig itself).

        SECURITY: The signature covers type, payload, msg_id, and ts.
        An attacker cannot replay, retype, or backdate a signed envelope
        without invalidating the signature.
        """
        canonical = json.dumps({
            "type": self.type,
            "payload": self.payload,
            "msg_id": self.msg_id,
            "ts": self.ts,
        }, sort_keys=True, separators=(",", ":"))
        return canonical

    def hash_digest(self) -> str:
        """SHA-256 of the full serialized envelope (including sig)."""
        return hashlib.sha256(self.to_json().encode()).hexdigest()

    # ----- Factory methods -----

    @classmethod
    def dht_put(cls, key: str, value_b64: str, salt: str,
                seq: int, ttl: int, nonce: int = 0) -> "Envelope":
        return cls(type="dht-put", payload={
            "key": key,
            "value": value_b64,
            "salt": salt,
            "seq": seq,
            "ttl": ttl,
            "nonce": nonce,
        })

    @classmethod
    def dht_get(cls, key: str) -> "Envelope":
        return cls(type="dht-get", payload={"key": key})

    @classmethod
    def dht_found(cls, key: str, value_b64: str, salt: str,
                  seq: int) -> "Envelope":
        return cls(type="dht-found", payload={
            "key": key,
            "value": value_b64,
            "salt": salt,
            "seq": seq,
        })

    @classmethod
    def dht_error(cls, key: str, message: str) -> "Envelope":
        return cls(type="dht-error", payload={
            "key": key, "message": message,
        })

    @classmethod
    def dht_addr_record(cls, null_id: str, address: str,
                        ttl: int, publisher_fp: str) -> "Envelope":
        """Signed address record proving ownership of a DHT key.

        The publisher signs: null_id|address|ttl
        This proves the publisher owns the private key for null_id.
        """
        return cls(type="dht-addr-record", payload={
            "null_id": null_id,
            "address": address,
            "ttl": ttl,
            "publisher_fp": publisher_fp,
        })

    @classmethod
    def p2p_hello(cls, public_key_b64: str, nonce: int,
                  pow_bits: int) -> "Envelope":
        return cls(type="p2p-hello", payload={
            "public_key": public_key_b64,
            "nonce": nonce,
            "pow_bits": pow_bits,
        })

    @classmethod
    def p2p_hello_ack(cls, public_key_b64: str, nonce: int,
                      pow_bits: int) -> "Envelope":
        return cls(type="p2p-hello-ack", payload={
            "public_key": public_key_b64,
            "nonce": nonce,
            "pow_bits": pow_bits,
        })

    @classmethod
    def p2p_message(cls, seq: int, ciphertext_b64: str,
                    msg_hash: str) -> "Envelope":
        return cls(type="p2p-message", payload={
            "seq": seq,
            "ciphertext": ciphertext_b64,
            "msg_hash": msg_hash,
        })

    @classmethod
    def p2p_ack(cls, seq: int, msg_hash: str) -> "Envelope":
        return cls(type="p2p-ack", payload={
            "seq": seq,
            "msg_hash": msg_hash,
        })

    @classmethod
    def p2p_ping(cls) -> "Envelope":
        return cls(type="p2p-ping")

    @classmethod
    def p2p_pong(cls) -> "Envelope":
        return cls(type="p2p-pong")

    @classmethod
    def nat_punch(cls, target_endpoint: str, nonce: str) -> "Envelope":
        return cls(type="nat-punch", payload={
            "target": target_endpoint,
            "nonce": nonce,
        })

    @classmethod
    def nat_punch_ack(cls, nonce: str) -> "Envelope":
        return cls(type="nat-punch-ack", payload={"nonce": nonce})

    # ----- Legacy relay factories (fallback) -----

    @classmethod
    def register(cls, null_id: str) -> "Envelope":
        return cls(type="register", payload={"null_id": null_id})

    @classmethod
    def registered(cls, null_id: str) -> "Envelope":
        return cls(type="registered", payload={"null_id": null_id})

    @classmethod
    def send(cls, sender: str, recipient: str, ciphertext_b64: str) -> "Envelope":
        return cls(type="send", payload={
            "from": sender, "to": recipient, "ciphertext": ciphertext_b64,
        })

    @classmethod
    def recv(cls, sender: str, ciphertext_b64: str,
             ts: float | None = None) -> "Envelope":
        return cls(type="recv", payload={
            "from": sender, "ciphertext": ciphertext_b64,
        }, ts=ts or time.time())

    @classmethod
    def ack(cls, ack_msg_id: str) -> "Envelope":
        return cls(type="ack", payload={"ack_msg_id": ack_msg_id})

    @classmethod
    def error(cls, message: str) -> "Envelope":
        return cls(type="error", payload={"message": message})

    @classmethod
    def route_advertise(cls, routes: dict[str, str] | None = None) -> "Envelope":
        return cls(type="route_advertise", payload={
            "routes": routes or {},
        })


# ------------------------------------------------------------------ #
#  Proof-of-work                                                     #
# ------------------------------------------------------------------ #

def pow_check(data: str, nonce: int, difficulty: int) -> bool:
    """Verify that SHA-256(data || nonce) has at least *difficulty* leading zero bits."""
    digest = hashlib.sha256(f"{data}{nonce}".encode()).digest()
    # Check leading zero bits
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
        else:
            # Count leading zeros in this non-zero byte
            b = byte
            while b > 0 and (b & 0x80) == 0:
                bits += 1
                b <<= 1
            break
    return bits >= difficulty


def pow_solve(data: str, difficulty: int, max_attempts: int = 10_000_000) -> int:
    """Find a nonce such that SHA-256(data || nonce) has *difficulty* leading zero bits.

    Returns the nonce, or raises RuntimeError if max_attempts exceeded.
    """
    for nonce in range(max_attempts):
        digest = hashlib.sha256(
            f"{data}{nonce}".encode()
        ).digest()
        # Check leading zero bits
        bits = 0
        for byte in digest:
            if byte == 0:
                bits += 8
            else:
                # Count leading zeros in this non-zero byte
                b = byte
                while b > 0 and (b & 0x80) == 0:
                    bits += 1
                    b <<= 1
                break
        if bits >= difficulty:
            return nonce
    raise RuntimeError(f"PoW solve failed after {max_attempts} attempts")
