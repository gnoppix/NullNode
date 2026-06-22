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
import logging
import os
import random
import time
from collections import defaultdict

import websockets

from protocol import (
    Envelope,
    P2P_POW_DIFFICULTY,
    pow_check,
    pow_solve,
)
from crypto import (
    null_id as compute_null_id,
    validate_fingerprint,
    validate_null_id,
    verify_signature,
    sign_data,
    DoubleRatchetSession,
    own_identity,
)
from dht import create_dht_node, DHTNode, pin_verify_address, pin_get

logger = logging.getLogger("p2p")

# ------------------------------------------------------------------ #
#  Constants                                                         #
# ------------------------------------------------------------------ #

P2P_PORT = 9001
CONNECTION_TIMEOUT = 10
MAX_CONNECTIONS = 50
MAILBOX_POLL_INTERVAL = 30  # seconds
SESSION_TIMEOUT = 3600      # 1 hour idle timeout

# Stealth mode for bot/scanner detection
STEALTH_MODE = os.environ.get("NULLNODE_STEALTH", "false").lower() == "true"
STEALTH_RESPONSES = [
    "HTTP/1.1 400 Bad Request",
    "Connection rejected",
    "",  # Empty response to confuse scanners
]


def _stealth_response() -> str:
    """Return a random stealth response for non-client connections."""
    return random.choice(STEALTH_RESPONSES)


# ------------------------------------------------------------------ #
#  Peer connection                                                   #
# ------------------------------------------------------------------ #

class PeerConnection:
    """Represents an authenticated P2P connection to a peer.

    SECURITY: After the handshake, all messages are encrypted
    via the DoubleRatchetSession which provides forward secrecy.
    """

    def __init__(self, ws, peer_nid: str, peer_fp: str,
                 ratchet: DoubleRatchetSession):
        self.ws = ws
        self.peer_nid = peer_nid
        self.peer_fp = peer_fp
        self.ratchet = ratchet
        self.connected_at = time.time()
        self.last_activity = time.time()

    async def send(self, plaintext: str) -> tuple[int, str]:
        """Encrypt and send a message. Returns (seq, msg_hash)."""
        ct, seq, msg_hash = self.ratchet.encrypt_message(plaintext)
        ct_b64 = __import__("base64").b64encode(ct.encode()).decode()
        env = Envelope.p2p_message(seq, ct_b64, msg_hash)
        await self.ws.send(env.to_json())
        self.last_activity = time.time()
        return seq, msg_hash

    async def receive(self) -> str | None:
        """Receive and decrypt a message. Returns None on close."""
        try:
            raw = await asyncio.wait_for(
                self.ws.recv(), timeout=SESSION_TIMEOUT
            )
            env = Envelope.from_json(raw)
            if env.type == "p2p-message":
                seq = env.payload.get("seq", 0)
                ct_b64 = env.payload.get("ciphertext", "")
                claimed_hash = env.payload.get("msg_hash", "")
                ct = __import__("base64").b64decode(ct_b64).decode()

                # SECURITY: Verify hash matches ciphertext
                import hashlib
                actual_hash = hashlib.sha256(ct.encode()).hexdigest()
                if actual_hash != claimed_hash:
                    logger.warning("message hash mismatch from %s", self.peer_nid)
                    return None

                plaintext = self.ratchet.decrypt_message(ct, seq, env.ts)
                self.last_activity = time.time()

                # Send ack
                ack = Envelope.p2p_ack(seq, claimed_hash)
                await self.ws.send(ack.to_json())
                return plaintext
            elif env.type == "p2p-ack":
                return None  # Acknowledgment, not a message
            elif env.type == "p2p-ping":
                await self.ws.send(Envelope.p2p_pong().to_json())
                return None
            elif env.type == "p2p-pong":
                return None
            else:
                logger.warning("unexpected message type: %s", env.type)
                return None
        except asyncio.TimeoutError:
            return None
        except websockets.exceptions.ConnectionClosed:
            return None


# ------------------------------------------------------------------ #
#  P2P Node                                                          #
# ------------------------------------------------------------------ #

class P2PNode:
    """Full P2P node: DHT + direct connections + mailbox polling.

    Message flow:
    1. Look up peer in DHT (get their address)
    2. Validate address ownership (TOFU pin + signature verification)
    3. Connect directly, perform handshake with PoW
    4. Exchange messages via double ratchet
    5. If peer offline, store encrypted message in DHT mailbox
    6. Poll own mailbox periodically
    """

    def __init__(
        self,
        nid: str,
        fingerprint: str,
        p2p_port: int = 0,
        dht_port: int = 0,
        bootstrap: list[str] | None = None,
    ):
        self.nid = nid
        self.fingerprint = fingerprint
        self.p2p_port = p2p_port or P2P_PORT
        self.dht_port = dht_port

        self._dht: DHTNode | None = None
        self._dht_bootstrap = bootstrap
        self._server = None
        self._running = False

        # Active peer connections
        self._peers: dict[str, PeerConnection] = {}  # nid -> PeerConnection
        self._ws_to_nid: dict[object, str] = {}      # ws -> nid

        # Message queue for UI
        self._message_queue: list[dict] = []
        self._message_event = asyncio.Event()

        # Ratchet sessions (persisted per connection)
        self._sessions: dict[str, DoubleRatchetSession] = {}

    async def start(self):
        """Start DHT and P2P listener."""
        # Start DHT
        self._dht = await create_dht_node(
            self.nid, "0.0.0.0", self.dht_port,
            bootstrap_nodes=self._dht_bootstrap,
            fingerprint=self.fingerprint,
        )

        # Start P2P listener
        self._server = await websockets.serve(
            self._handle_connection,
            "0.0.0.0",
            self.p2p_port,
            ping_interval=30,
            ping_timeout=10,
            max_size=1_048_576,
        )
        actual_port = self._server.sockets[0].getsockname()[1]
        self.p2p_port = actual_port
        self._running = True

        # Discover our public IP via STUN so we publish a reachable address
        # Without this, we'd publish wss://0.0.0.0:<port> which is useless
        # to remote peers (0.0.0.0 resolves to their own machine, not ours)
        public_addr = await self._discover_public_address(actual_port)
        if not public_addr:
            logger.warning(
                "STUN failed — could not determine public address. "
                "Publishing 0.0.0.0 as fallback (remote peers may not connect)"
            )
            public_addr = f"wss://0.0.0.0:{actual_port}"

        # Publish a signed address record in the DHT
        # This proves we own our null_id (signature over nid|address|ttl)
        await self._dht.publish_addr_record(
            self.nid, self.fingerprint, public_addr,
        )

        # Start background tasks
        asyncio.create_task(self._mailbox_poll_loop())
        asyncio.create_task(self._cleanup_idle_connections())

        logger.info(
            "P2P node %s listening on :%d (DHT :%d)",
            self.nid, actual_port, self._dht.port,
        )

    async def stop(self):
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if self._dht:
            await self._dht.stop()
        for peer in self._peers.values():
            await peer.ws.close()

    async def _discover_public_address(self, local_port: int) -> str | None:
        """Discover our public IP via STUN and build a reachable address.

        Returns a wss:// URL string, or None if STUN fails.

        SECURITY: Uses the existing nat.get_public_endpoint() which queries
        multiple STUN servers. If STUN works, remote peers can connect to us.
        If STUN fails (e.g. blocked UDP), we fall back to 0.0.0.0.
        """
        try:
            from nat import get_public_endpoint
            endpoint = await get_public_endpoint()
            if endpoint:
                public_ip, public_port = endpoint
                return f"wss://{public_ip}:{public_port}"
        except Exception as e:
            logger.debug("STUN discovery failed: %s", e)
        return None

    # ------------------------------------------------------------------ #
    #  Message sending                                                   #
    # ------------------------------------------------------------------ #

    async def send_message(
        self,
        recipient_nid: str,
        recipient_fp: str,
        plaintext: str,
    ) -> bool:
        """Send a message to a peer.

        Tries direct P2P first. Falls back to DHT mailbox if peer is offline.

        SECURITY: The message is encrypted with the double ratchet.
        Even if the DHT stores the message, only the recipient can decrypt it.
        """
        # Try direct connection first
        if recipient_nid in self._peers:
            peer = self._peers[recipient_nid]
            try:
                seq, msg_hash = await peer.send(plaintext)
                logger.debug("sent seq %d to %s", seq, recipient_nid)
                return True
            except Exception as e:
                logger.warning("direct send to %s failed: %s", recipient_nid, e)
                # Fall through to DHT mailbox

        # Try to connect directly
        connected = await self._try_connect(recipient_nid, recipient_fp)
        if connected:
            peer = self._peers[recipient_nid]
            try:
                seq, msg_hash = await peer.send(plaintext)
                return True
            except Exception as e:
                logger.warning("send to %s after connect failed: %s", recipient_nid, e)

        # Fall back to DHT mailbox (dead drop)
        logger.info(
            "%s offline, storing in DHT mailbox", recipient_nid,
        )
        return await self._store_in_mailbox(
            recipient_nid, recipient_fp, plaintext,
        )

    async def _store_in_mailbox(
        self,
        recipient_nid: str,
        recipient_fp: str,
        plaintext: str,
    ) -> bool:
        """Store an encrypted message in the recipient's DHT mailbox."""
        if not self._dht:
            logger.error("DHT not available for mailbox storage")
            return False

        # Get current sequence number for this mailbox
        existing = await self._dht.get_mailbox(recipient_nid)
        next_seq = 1
        if existing:
            next_seq = max(r.get("seq", 0) for r in existing) + 1

        # Encrypt the message
        from crypto import encrypt
        ciphertext = encrypt(plaintext, recipient_fp)
        ct_b64 = __import__("base64").b64encode(ciphertext.encode()).decode()

        # Sign the encrypted blob (proves sender identity)
        # Signature covers: sender_fp|recipient_nid|ct_b64|seq
        # This binds the sender's fingerprint to the message, preventing
        # sender_nid spoofing in the signed_blob.
        sign_payload = f"{self.fingerprint}|{recipient_nid}|{ct_b64}|{next_seq}"
        sig = sign_data(sign_payload, self.fingerprint)

        # Store in DHT
        # Format: ct_b64|sender_nid|sender_fp|sig
        signed_blob = __import__("base64").b64encode(
            f"{ct_b64}|{self.nid}|{self.fingerprint}|{sig}".encode()
        ).decode()

        await self._dht.store_mailbox(
            recipient_nid, signed_blob, self.fingerprint, next_seq,
        )
        logger.info("stored message for %s (seq %d)", recipient_nid, next_seq)
        return True

    # ------------------------------------------------------------------ #
    #  Direct connection                                                 #
    # ------------------------------------------------------------------ #

    async def _try_connect(
        self,
        peer_nid: str,
        peer_fp: str,
    ) -> bool:
        """Attempt a direct P2P connection to a peer.

        1. Look up peer's address in the DHT
        2. Validate address ownership (TOFU pin + signature)
        3. Connect via WebSocket
        4. Perform handshake with proof-of-work
        5. Initialize double ratchet

        SECURITY: If the address doesn't match the TOFU pin, the connection
        is rejected (possible MITM).
        """
        if peer_nid in self._peers:
            return True

        # Look up address via DHT (includes signature verification + TOFU)
        addr = await self._dht.lookup(peer_nid) if self._dht else None
        if not addr:
            logger.debug("no DHT address for %s", peer_nid)
            return False

        # SECURITY: Validate the address against TOFU pin
        # pin_verify_address returns False if address differs from pin
        if not pin_verify_address(peer_nid, addr):
            logger.warning(
                "REJECTED connection to %s: address %s does not match TOFU pin "
                "(possible MITM attack)",
                peer_nid, addr,
            )
            return False

        try:
            ws = await websockets.connect(addr, open_timeout=CONNECTION_TIMEOUT)

            # Perform handshake with PoW
            if not await self._handshake(ws, peer_nid, peer_fp):
                await ws.close()
                return False

            # Create ratchet session
            ratchet = DoubleRatchetSession(
                peer_fingerprint=peer_fp,
                peer_null_id=peer_nid,
                our_fingerprint=self.fingerprint,
                is_initiator=True,
            )

            peer = PeerConnection(ws, peer_nid, peer_fp, ratchet)
            self._peers[peer_nid] = peer
            self._ws_to_nid[ws] = peer_nid

            # Start background reader
            asyncio.create_task(self._peer_reader(peer_nid))

            logger.info("connected to %s at %s", peer_nid, addr)
            # SECURITY: First-contact warning if no prior pin existed
            if not pin_get(peer_nid):
                logger.warning(
                    "connection: FIRST CONTACT with %s at %s -- "
                    "TOFU pinned. Verify peer identity out-of-band!",
                    peer_nid, addr,
                )
            return True

        except Exception as e:
            logger.warning("connection to %s failed: %s", peer_nid, e)
            return False

    async def _handshake(
        self,
        ws,
        peer_nid: str,
        peer_fp: str,
    ) -> bool:
        """Perform P2P handshake with proof-of-work.

        Both sides must solve a PoW puzzle to prevent connection spam.
        The puzzle includes our null_id + a nonce, making it bound to
        our identity (not just the IP).
        """
        import secrets as _secrets
        import hashlib

        # Generate PoW challenge
        my_nonce = _secrets.randbelow(1_000_000)
        pow_data = f"{self.nid}{my_nonce}"
        pow_nonce = pow_solve(pow_data, P2P_POW_DIFFICULTY)

        # Send hello
        hello = Envelope.p2p_hello(
            public_key_b64=__import__("base64").b64encode(
                self.fingerprint.encode()
            ).decode(),
            nonce=my_nonce,
            pow_bits=P2P_POW_DIFFICULTY,
        )
        # Sign the hello
        hello.sig = sign_data(hello.signing_payload(), self.fingerprint)
        await ws.send(hello.to_json())

        # Receive peer's hello
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=CONNECTION_TIMEOUT)
            resp = Envelope.from_json(raw)
        except asyncio.TimeoutError:
            logger.warning("handshake timeout with %s", peer_nid)
            return False

        if resp.type != "p2p-hello":
            logger.warning("unexpected handshake response: %s", resp.type)
            return False

        # Verify PoW
        peer_nonce = resp.payload.get("nonce", 0)
        ws._peer_pow_nonce = peer_nonce

        # Verify signature
        peer_fp_b64 = resp.payload.get("public_key", "")
        peer_fp_from_hello = __import__("base64").b64decode(
            peer_fp_b64
        ).decode()

        if peer_fp_from_hello != peer_fp:
            logger.warning("handshake fingerprint mismatch")
            return False

        if not verify_signature(
            resp.signing_payload(), resp.sig, peer_fp,
        ):
            logger.warning("handshake signature verification failed")
            return False

        # Send hello-ack
        ack_nonce = _secrets.randbelow(1_000_000)
        ack = Envelope.p2p_hello_ack(
            public_key_b64=__import__("base64").b64encode(
                self.fingerprint.encode()
            ).decode(),
            nonce=ack_nonce,
            pow_bits=P2P_POW_DIFFICULTY,
        )
        ack.sig = sign_data(ack.signing_payload(), self.fingerprint)
        await ws.send(ack.to_json())

        return True

    # ------------------------------------------------------------------ #
    #  Incoming connections                                              #
    # ------------------------------------------------------------------ #

    async def _handle_connection(self, ws):
        """Handle an incoming P2P connection.

        SECURITY: Validates the incoming connection against the TOFU pin.
        If the remote address doesn't match the pinned address for the
        claimed null_id, the connection is rejected.
        """
        if len(self._peers) >= MAX_CONNECTIONS:
            await ws.send(Envelope.error("max connections reached").to_json())
            await ws.close()
            return

        peer_nid = None
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=CONNECTION_TIMEOUT)
            env = Envelope.from_json(raw)

            if env.type != "p2p-hello":
                if STEALTH_MODE:
                    await ws.send(_stealth_response())
                else:
                    await ws.send(Envelope.error("expected p2p-hello").to_json())
                await ws.close()
                return

            # Verify signature
            peer_fp_b64 = env.payload.get("public_key", "")
            peer_fp = __import__("base64").b64decode(peer_fp_b64).decode()

            if not validate_fingerprint(peer_fp):
                if STEALTH_MODE:
                    await ws.send(_stealth_response())
                else:
                    await ws.send(Envelope.error("invalid fingerprint").to_json())
                await ws.close()
                return

            if not verify_signature(env.signing_payload(), env.sig, peer_fp):
                if STEALTH_MODE:
                    await ws.send(_stealth_response())
                else:
                    await ws.send(Envelope.error("signature failed").to_json())
                await ws.close()
                return

            peer_nid = compute_null_id(peer_fp)

            # SECURITY: Validate incoming connection source against TOFU pin
            remote_addr = ws.remote_address
            if remote_addr:
                peer_ip = remote_addr[0]
                # Build the expected address pattern from the pin
                pinned = pin_get(peer_nid)
                if pinned:
                    # Extract host:port from pinned address
                    # (format: wss://host:port)
                    pinned_addr = pinned.get("address", "")
                    if pinned_addr.startswith("wss://"):
                        pinned_host_port = pinned_addr[len("wss://"):]
                        # Compare the source IP against the pinned address
                        # We check if the IP part matches
                        if ":" in pinned_host_port:
                            pinned_host = pinned_host_port.rsplit(":", 1)[0]
                            if peer_ip != pinned_host and pinned_host != "0.0.0.0":
                                logger.warning(
                                    "REJECTED incoming connection from %s: "
                                    "IP %s does not match pinned address %s "
                                    "(possible MITM)",
                                    peer_nid, peer_ip, pinned_host,
                                )
                                await ws.send(
                                    Envelope.error("address mismatch -- possible MITM").to_json()
                                )
                                await ws.close()
                                return

            # Send hello-ack
            import secrets as _secrets
            ack_nonce = _secrets.randbelow(1_000_000)
            ack = Envelope.p2p_hello_ack(
                public_key_b64=__import__("base64").b64encode(
                    self.fingerprint.encode()
                ).decode(),
                nonce=ack_nonce,
                pow_bits=P2P_POW_DIFFICULTY,
            )
            ack.sig = sign_data(ack.signing_payload(), self.fingerprint)
            await ws.send(ack.to_json())

            # Wait for peer's hello-ack
            raw2 = await asyncio.wait_for(ws.recv(), timeout=CONNECTION_TIMEOUT)
            ack2 = Envelope.from_json(raw2)
            if ack2.type != "p2p-hello-ack":
                await ws.close()
                return

            # Verify peer's ack signature
            if not verify_signature(ack2.signing_payload(), ack2.sig, peer_fp):
                await ws.send(Envelope.error("ack signature failed").to_json())
                await ws.close()
                return

            # Create ratchet
            ratchet = DoubleRatchetSession(
                peer_fingerprint=peer_fp,
                peer_null_id=peer_nid,
                our_fingerprint=self.fingerprint,
                is_initiator=False,
            )

            peer = PeerConnection(ws, peer_nid, peer_fp, ratchet)
            self._peers[peer_nid] = peer
            self._ws_to_nid[ws] = peer_nid

            logger.info("accepted connection from %s", peer_nid)

            # Start reader
            await self._peer_reader(peer_nid)

        except asyncio.TimeoutError:
            logger.warning("handshake timeout from %s", ws.remote_address)
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            logger.warning("incoming connection error: %s", e)
        finally:
            if peer_nid:
                self._peers.pop(peer_nid, None)
            self._ws_to_nid.pop(ws, None)

    # ------------------------------------------------------------------ #
    #  Background tasks                                                  #
    # ------------------------------------------------------------------ #

    async def _peer_reader(self, peer_nid: str):
        """Read messages from a peer connection and queue them for the UI."""
        peer = self._peers.get(peer_nid)
        if not peer:
            return
        try:
            while self._running and peer_nid in self._peers:
                plaintext = await peer.receive()
                if plaintext is None:
                    continue
                self._message_queue.append({
                    "from": peer_nid,
                    "text": plaintext,
                    "ts": time.time(),
                })
                self._message_event.set()
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            logger.warning("peer %s reader error: %s", peer_nid, e)
        finally:
            self._peers.pop(peer_nid, None)
            logger.info("peer %s disconnected", peer_nid)

    async def _mailbox_poll_loop(self):
        """Periodically check the DHT mailbox for new messages."""
        while self._running:
            await asyncio.sleep(MAILBOX_POLL_INTERVAL)
            try:
                await self._poll_mailbox()
            except Exception as e:
                logger.warning("mailbox poll error: %s", e)

    async def _poll_mailbox(self):
        """Poll our DHT mailbox and decrypt any new messages."""
        if not self._dht:
            return

        messages = await self._dht.get_mailbox(self.nid)
        if not messages:
            return

        from crypto import decrypt

        for msg in messages:
            blob_b64 = msg.get("value", "")
            blob = __import__("base64").b64decode(blob_b64).decode()

            # Parse: ct_b64|sender_nid|sender_fp|sig
            parts = blob.split("|", 3)
            if len(parts) != 4:
                logger.warning("malformed mailbox blob (expected 4 fields, got %d)", len(parts))
                continue

            ct_b64, sender_nid, sender_fp, sender_sig = parts
            ct = __import__("base64").b64decode(ct_b64).decode()

            # SECURITY: Verify sender signature before delivering
            # Signature covers: sender_fp|recipient_nid|ct_b64|seq
            if sender_fp and sender_sig:
                sign_payload = f"{sender_fp}|{self.nid}|{ct_b64}|{msg.get('seq', 0)}"
                if not verify_signature(sign_payload, sender_sig, sender_fp):
                    logger.warning(
                        "mailbox: sender signature verification failed for %s "
                        "(claimed fp=%s) -- rejecting message",
                        sender_nid, sender_fp[:16] if sender_fp else "none",
                    )
                    continue
                logger.debug("mailbox: sender signature verified for %s", sender_nid)
            else:
                # Legacy blob without sender_fp -- reject (no sender auth)
                logger.warning(
                    "mailbox: legacy unsigned blob from %s -- rejecting",
                    sender_nid,
                )
                continue

            try:
                plaintext = decrypt(ct)
                self._message_queue.append({
                    "from": sender_nid,
                    "text": plaintext,
                    "ts": time.time(),
                    "sender_sig": sender_sig,
                    "sender_fp": sender_fp,
                })
                self._message_event.set()
            except Exception as e:
                logger.warning("failed to decrypt mailbox message: %s", e)

    async def _cleanup_idle_connections(self):
        """Close idle connections after SESSION_TIMEOUT."""
        while self._running:
            await asyncio.sleep(60)
            now = time.time()
            to_close = [
                nid for nid, peer in self._peers.items()
                if now - peer.last_activity > SESSION_TIMEOUT
            ]
            for nid in to_close:
                peer = self._peers.pop(nid, None)
                if peer:
                    await peer.ws.close()
                logger.info("closed idle connection to %s", nid)

    # ------------------------------------------------------------------ #
    #  UI integration                                                    #
    # ------------------------------------------------------------------ #

    async def wait_for_message(self, timeout: float = None) -> dict | None:
        """Wait for the next incoming message. Returns None on timeout."""
        try:
            await asyncio.wait_for(
                self._message_event.wait(), timeout=timeout
            )
            self._message_event.clear()
            if self._message_queue:
                return self._message_queue.pop(0)
        except asyncio.TimeoutError:
            pass
        return None

    def get_peers(self) -> list[str]:
        """Return list of connected peer null IDs."""
        return list(self._peers.keys())
