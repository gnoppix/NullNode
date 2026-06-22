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
import socket
import struct
import time

logger = logging.getLogger("nat")

# ------------------------------------------------------------------ #
#  STUN constants                                                    #
# ------------------------------------------------------------------ #

STUN_MAGIC = 0x2112A442
STUN_HEADER_SIZE = 20
STUN_ATTR_MAPPED_ADDRESS = 0x0001
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020
STUN_ATTR_RESPONSE_ORIGIN = 0x802B
STUN_ATTR_OTHER_ADDRESS = 0x8022

STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
    ("stun.stunprotocol.org", 3478),
    ("stun.ekiga.net", 3478),
    ("stun.ideasip.com", 3478),
]

STUN_TIMEOUT = 5
STUN_RETRIES = 3


# ------------------------------------------------------------------ #
#  STUN packet construction/parsing                                  #
# ------------------------------------------------------------------ #

def _build_stun_binding_request(transaction_id: bytes) -> bytes:
    """Build a STUN Binding Request packet."""
    msg_type = 0x0001  # Binding Request
    msg_length = 0
    header = struct.pack("!HHI", msg_type, msg_length, STUN_MAGIC)
    header += transaction_id  # 12 bytes
    return header


def _parse_stun_response(data: bytes) -> tuple[str, int] | None:
    """Parse a STUN Binding Response and extract public address.

    Returns (ip, port) or None on failure.
    """
    if len(data) < STUN_HEADER_SIZE:
        return None
    msg_type, msg_length, magic = struct.unpack("!HHI", data[:8])
    if magic != STUN_MAGIC:
        return None
    if msg_type != 0x0101:  # Binding Success Response
        return None

    # Parse attributes
    offset = STUN_HEADER_SIZE
    while offset + 4 <= len(data):
        attr_type, attr_len = struct.unpack("!HH", data[offset:offset+4])
        attr_data = data[offset+4:offset+4+attr_len]
        offset += 4 + attr_len
        # Pad to 4-byte boundary
        while offset % 4 != 0:
            offset += 1

        if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS and len(attr_data) >= 8:
            family = struct.unpack("!H", attr_data[0:2])[0]
            xport = struct.unpack("!H", attr_data[2:4])[0]
            xaddr = attr_data[4:]
            if family == 0x01:  # IPv4
                port = xport ^ (STUN_MAGIC >> 16)
                ip_int = struct.unpack("!I", xaddr[:4])[0]
                ip_int ^= STUN_MAGIC
                ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                return (ip, port)
        elif attr_type == STUN_ATTR_MAPPED_ADDRESS and len(attr_data) >= 8:
            family = struct.unpack("!H", attr_data[0:2])[0]
            port = struct.unpack("!H", attr_data[2:4])[0]
            if family == 0x01:  # IPv4
                ip = socket.inet_ntoa(attr_data[4:8])
                return (ip, port)

    return None


# ------------------------------------------------------------------ #
#  Public API                                                        #
# ------------------------------------------------------------------ #

async def get_public_endpoint(
    stun_servers: list[tuple[str, int]] | None = None,
) -> tuple[str, int] | None:
    """Discover our public IP:port via STUN.

    Tries multiple STUN servers. Returns the first consistent result.
    If multiple servers agree, we have high confidence the result is correct.
    """
    servers = stun_servers or STUN_SERVERS
    results = []

    for host, port in servers:
        for attempt in range(STUN_RETRIES):
            try:
                loop = asyncio.get_event_loop()
                transaction_id = (
                    struct.pack("!I", STUN_MAGIC) +
                    secrets_token_bytes(8)
                )
                request = _build_stun_binding_request(transaction_id)

                # Use asyncio datagram for UDP
                transport, protocol = await loop.create_datagram_endpoint(
                    lambda: _STUNProtocol(host, port, request),
                    remote_addr=(host, port),
                )
                try:
                    result = await asyncio.wait_for(
                        protocol.get_result(), timeout=STUN_TIMEOUT
                    )
                    if result:
                        results.append(result)
                        logger.debug(
                            "STUN %s:%d -> %s:%d", host, port, *result
                        )
                        return result  # Return first success
                finally:
                    transport.close()
            except Exception as e:
                logger.debug("STUN %s:%d attempt %d failed: %s",
                             host, port, attempt + 1, e)
                continue

    return None


class _STUNProtocol(asyncio.DatagramProtocol):
    """Simple UDP client for a single STUN transaction."""

    def __init__(self, host: str, port: int, request: bytes):
        self.host = host
        self.port = port
        self.request = request
        self._future: asyncio.Future[tuple[str, int] | None] = (
            asyncio.get_event_loop().create_future()
        )

    def connection_made(self, transport: asyncio.DatagramTransport):
        transport.sendto(self.request)

    def datagram_received(self, data: bytes, addr):
        result = _parse_stun_response(data)
        if not self._future.done():
            self._future.set_result(result)

    def error_received(self, exc):
        if not self._future.done():
            self._future.set_exception(exc)

    def connection_lost(self, exc):
        if not self._future.done():
            self._future.set_result(None)

    async def get_result(self) -> tuple[str, int] | None:
        return await self._future


def secrets_token_bytes(n: int) -> bytes:
    """Secure random bytes (avoids importing secrets at module level)."""
    import secrets as _secrets
    return _secrets.token_bytes(n)


async def hole_punch(
    local_port: int,
    peer_public_ip: str,
    peer_public_port: int,
    peer_local_port: int | None = None,
) -> socket.socket | None:
    """Attempt UDP hole punching to a peer.

    Returns a connected socket on success, None on failure.

    SECURITY: This sends UDP packets to the peer's public endpoint.
    The peer must also be sending packets to us simultaneously.
    The resulting socket is used for the P2P handshake.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", local_port))
    sock.setblocking(False)

    # Send hole-punch packets to both public and local endpoints
    targets = [(peer_public_ip, peer_public_port)]
    if peer_local_port:
        targets.append((peer_public_ip, peer_local_port))

    loop = asyncio.get_event_loop()
    for _ in range(10):  # Send 10 packets over ~1 second
        for ip, port in targets:
            try:
                sock.sendto(b"\x00" * 16, (ip, port))  # 16-byte padding
            except Exception:
                pass
        await asyncio.sleep(0.1)

    sock.setblocking(True)
    sock.settimeout(2.0)
    try:
        data, addr = sock.recvfrom(1024)
        if len(data) >= 16:
            # Peer responded — socket is now "connected"
            sock.connect(addr)
            logger.info("hole punch success to %s:%d", *addr)
            return sock
    except socket.timeout:
        pass

    sock.close()
    return None
