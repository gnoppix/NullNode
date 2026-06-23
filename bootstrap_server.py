#!/usr/bin/env python3
#-------------------------------------------------------------------------------
# Name: Gnoppix Linux - Services
# Architecture: all
# Date: 2002-2026 by Gnoppix Linux
# Author: Andreas Mueller
# Website: https://www.gnoppix.com
# Licence: Business Source License (BSL / BUSL)
# You can use the code for free if your company or organisation doesn't have more than 2 people.
#-------------------------------------------------------------------------------
"""
NullNode Bootstrap / Phonebook Server

Runs a public DHT bootstrap node that acts as a phonebook for the NullNode
P2P network. Other clients connect to it to join the DHT and look up addresses.

This server does NOT need a GPG identity — it only serves DHT routing data
and stores encrypted mailbox blobs. It cannot read message content.

Usage:
  python3 bootstrap_server.py

Environment variables:
  NULLNODE_BOOTSTRAP_PORT    Listen port (default: 9001)
  NULLNODE_BOOTSTRAP_HOST    Bind address (default: 0.0.0.0)
  NULLNODE_BOOTSTRAP_ID      Null ID for this node (default: auto-generated)
  NULLNODE_BOOTSTRAP_CERT    Path to TLS certificate (PEM) — enables wss://
  NULLNODE_BOOTSTRAP_KEY     Path to TLS private key (PEM) — enables wss://
  NULLNODE_STEALTH           Set to "true" to enable stealth mode
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys

from dht import DHTNode, DHTStore, node_id_from_nid

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("bootstrap")

HOST = os.environ.get("NULLNODE_BOOTSTRAP_HOST", "0.0.0.0")
PORT = int(os.environ.get("NULLNODE_BOOTSTRAP_PORT", "9001"))
NID = os.environ.get("NULLNODE_BOOTSTRAP_ID", "")
SSL_CERTFILE = os.environ.get("NULLNODE_BOOTSTRAP_CERT", "")
SSL_KEYFILE = os.environ.get("NULLNODE_BOOTSTRAP_KEY", "")


def _generate_nid() -> str:
    """Generate a random Null ID for this bootstrap node."""
    import hashlib
    import base64
    import secrets
    raw = secrets.token_bytes(8)
    h = hashlib.blake2b(raw, digest_size=8).digest()
    b32 = base64.b32encode(h).decode().lower().rstrip("=")
    return f"NN-{b32[:4]}-{b32[4:8]}"


async def main():
    nid = NID or _generate_nid()
    logger.info("starting bootstrap server")
    logger.info("  Null ID : %s", nid)
    logger.info("  listen  : %s:%d", HOST, PORT)

    store = DHTStore(db_path=os.path.expanduser("~/.nullnode/bootstrap_dht.db"))
    node = DHTNode(nid, HOST, PORT, fingerprint="", store=store,
                   ssl_certfile=SSL_CERTFILE, ssl_keyfile=SSL_KEYFILE)
    await node.start(PORT)

    actual_port = node.port
    scheme = "wss" if (SSL_CERTFILE and SSL_KEYFILE) else "ws"
    logger.info("  address : %s://%s:%d", scheme, HOST, actual_port)
    logger.info("  node ID : 0x%x", node.node_id)
    logger.info("  ready — waiting for DHT connections")

    # Run forever until interrupted
    stop_event = asyncio.Event()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)

    try:
        await stop_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("shutting down bootstrap server...")
        await node.stop()
        logger.info("stopped")


if __name__ == "__main__":
    asyncio.run(main())
