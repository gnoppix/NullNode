#-------------------------------------------------------------------------------
# Name: Gnoppix Linux - Services
# Architecture: all
# Date: 2002-2006 by Gnoppix Linux
# Author: Andreas Mueller
# Website: https://www.gnoppix.com
# Licence: Business Source License (BSL / BUSL)
#-------------------------------------------------------------------------------
from __future__ import annotations

import argparse
import asyncio
import base64
import os
import sys
import time

from crypto import (
    generate_keypair,
    null_id,
    encrypt,
    decrypt,
    export_pubkey,
    import_pubkey,
    own_identity,
    validate_null_id,
    register_contact,
    resolve_contact,
    list_contacts,
    get_fingerprint_from_armored,
    sign_data,
)
from protocol import Envelope
from p2p import P2PNode
from dht import create_dht_node

RELAY_URL = os.environ.get("NULLNODE_RELAY", "ws://127.0.0.1:8765")
DHT_BOOTSTRAP = os.environ.get("NULLNODE_DHT_BOOTSTRAP", "")


# ------------------------------------------------------------------ #
#  Identity commands                                                 #
# ------------------------------------------------------------------ #

def cmd_init(args):
    try:
        fp = generate_keypair()
        nid = null_id(fp)
        print(f"identity created: {nid}")
        print(f"fingerprint: {fp}")
        print(f"gpg homedir: {os.path.dirname(os.path.expanduser('~/.nullnode/gnupg'))}")
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_id(args):
    try:
        nid, fp = own_identity()
        print(f"Null ID:     {nid}")
        print(f"fingerprint: {fp}")
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_export(args):
    try:
        pk = export_pubkey()
        print(pk, end="")
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_import(args):
    try:
        if args.file:
            with open(args.file) as f:
                armored = f.read()
        else:
            armored = sys.stdin.read()
        fp = import_pubkey(armored)
        nid = null_id(fp)
        print(f"imported: {nid}")
        print(f"fingerprint: {fp}")
        if args.alias:
            register_contact(args.alias, fp)
            print(f"registered as contact: {args.alias}")
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_contacts(args):
    contacts = list_contacts()
    if not contacts:
        print("no contacts registered")
        return
    for nid, fp in contacts.items():
        print(f"{nid}  {fp}")


# ------------------------------------------------------------------ #
#  P2P commands                                                      #
# ------------------------------------------------------------------ #

async def cmd_p2p_listen(args):
    """Start a P2P node and listen for incoming connections."""
    try:
        my_nid, my_fp = own_identity()
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return

    bootstrap = None
    if args.bootstrap:
        bootstrap = args.bootstrap.split(",")
    elif DHT_BOOTSTRAP:
        bootstrap = DHT_BOOTSTRAP.split(",")

    node = P2PNode(
        nid=my_nid,
        fingerprint=my_fp,
        p2p_port=args.port or 0,
        bootstrap=bootstrap,
    )
    await node.start()

    print(f"P2P listening as {my_nid}", flush=True)
    print(f"fingerprint: {my_fp}", flush=True)
    print(f"peers: {node.get_peers()}", flush=True)
    print("Waiting for messages... Press Ctrl+C to stop.\n", flush=True)

    try:
        while True:
            msg = await node.wait_for_message(timeout=1)
            if msg:
                sender = msg.get("from", "?")
                text = msg.get("text", "")
                print(f"\r[{sender}] {text}", flush=True)
                print("> ", end="", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        await node.stop()


async def cmd_send(args):
    """Send a message to a peer via P2P or DHT mailbox."""
    try:
        my_nid, my_fp = own_identity()
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return

    recipient_nid = args.recipient.upper()
    if not validate_null_id(recipient_nid):
        print(f"invalid Null ID: {recipient_nid}")
        return

    if args.fingerprint:
        recipient_fp = args.fingerprint
    else:
        recipient_fp = resolve_contact(recipient_nid)
        if not recipient_fp:
            print(f"no contact '{recipient_nid}' — provide --fingerprint")
            return

    # Start a temporary P2P node
    bootstrap = None
    if args.bootstrap:
        bootstrap = args.bootstrap.split(",")
    elif DHT_BOOTSTRAP:
        bootstrap = DHT_BOOTSTRAP.split(",")

    node = P2PNode(
        nid=my_nid,
        fingerprint=my_fp,
        bootstrap=bootstrap,
    )
    await node.start()

    try:
        success = await node.send_message(
            recipient_nid, recipient_fp, args.message,
        )
        if success:
            print(f"message sent to {recipient_nid}")
        else:
            print(f"failed to send to {recipient_nid}")
    finally:
        await node.stop()


async def cmd_chat(args):
    """Interactive P2P chat session."""
    try:
        my_nid, my_fp = own_identity()
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return

    peer_nid = args.peer.upper()
    if not validate_null_id(peer_nid):
        print(f"invalid Null ID: {peer_nid}")
        return

    if args.fingerprint:
        peer_fp = args.fingerprint
    else:
        peer_fp = resolve_contact(peer_nid)
        if not peer_fp:
            print(f"no contact '{peer_nid}' — provide --fingerprint")
            return

    bootstrap = None
    if args.bootstrap:
        bootstrap = args.bootstrap.split(",")
    elif DHT_BOOTSTRAP:
        bootstrap = DHT_BOOTSTRAP.split(",")

    node = P2PNode(
        nid=my_nid,
        fingerprint=my_fp,
        bootstrap=bootstrap,
    )
    await node.start()

    print(f"you: {my_nid}  ({my_fp})")
    print(f"peer: {peer_nid}  ({peer_fp})")
    print("connecting...\n", flush=True)

    # Try to connect
    connected = await node._try_connect(peer_nid, peer_fp)
    if not connected:
        print(f"could not reach {peer_nid} — will try when they come online")
        print("messages will be delivered via DHT mailbox\n")

    async def reader():
        while True:
            msg = await node.wait_for_message(timeout=1)
            if msg:
                sender = msg.get("from", "?")
                text = msg.get("text", "")
                print(f"\r[{sender}] {text}")
                print("> ", end="", flush=True)

    async def writer():
        while True:
            line = await asyncio.get_event_loop().run_in_executor(
                None, sys.stdin.readline
            )
            line = line.strip()
            if not line:
                continue
            if line == "/quit":
                return
            success = await node.send_message(peer_nid, peer_fp, line)
            if not success:
                print(f"\r<failed to send>")
            print("> ", end="", flush=True)

    try:
        await asyncio.gather(reader(), writer())
    except KeyboardInterrupt:
        pass
    finally:
        await node.stop()


async def cmd_dht(args):
    """DHT diagnostic commands."""
    try:
        my_nid, my_fp = own_identity()
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return

    port = args.port or 0
    bootstrap = []
    if args.bootstrap:
        bootstrap = args.bootstrap.split(",")
    elif DHT_BOOTSTRAP:
        bootstrap = DHT_BOOTSTRAP.split(",")

    node = await create_dht_node(
        my_nid, "0.0.0.0", port,
        bootstrap if bootstrap else None,
        fingerprint=my_fp,
    )
    print(f"DHT node started on port {node.port}")
    print(f"node ID: {hex(node.node_id)}")
    print(f"stored keys: {node.store.count_keys()}")

    if args.find:
        result = await node.lookup(args.find.upper())
        if result:
            print(f"found {args.find.upper()} -> {result}")
        else:
            print(f"{args.find.upper()} not found in DHT")

    if args.advertise:
        advertise_addr = args.advertise if isinstance(args.advertise, str) else None
        await node.advertise_address(my_nid, my_fp, advertise_addr=advertise_addr)
        where = advertise_addr or node.address
        print(f"advertised {my_nid} -> {where}")

    print("DHT running. Press Ctrl+C to stop.")
    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass
    finally:
        await node.stop()


# ------------------------------------------------------------------ #
#  CLI entry point                                                   #
# ------------------------------------------------------------------ #

def main():
    parser = argparse.ArgumentParser(
        prog="nullnode",
        description="NullNode P2P encrypted messenger",
    )
    sub = parser.add_subparsers(dest="command")

    # Identity
    sub.add_parser("init", help="Generate post-quantum keypair")
    sub.add_parser("id", help="Show your identity")
    sub.add_parser("export", help="Export public key")
    p_import = sub.add_parser("import", help="Import a peer's public key")
    p_import.add_argument("file", nargs="?", help="path to armored key file")
    p_import.add_argument("--alias", help="register as contact with this Null ID")
    sub.add_parser("contacts", help="List contacts")

    # P2P
    p_p2p = sub.add_parser("p2p", help="Start P2P node and listen for messages")
    p_p2p.add_argument("--port", type=int, help="P2P port")
    p_p2p.add_argument("--bootstrap", help="Comma-separated bootstrap DHT seeds")

    p_send = sub.add_parser("send", help="Send a message to a peer")
    p_send.add_argument("recipient", help="Recipient Null ID (NN-XXXX-XXXX)")
    p_send.add_argument("message", help="Message to send")
    p_send.add_argument("--fingerprint", help="Recipient's GPG fingerprint")
    p_send.add_argument("--bootstrap", help="Comma-separated bootstrap DHT seeds")

    p_chat = sub.add_parser("chat", help="Interactive P2P chat")
    p_chat.add_argument("peer", help="Peer Null ID (NN-XXXX-XXXX)")
    p_chat.add_argument("--fingerprint", help="Peer's GPG fingerprint")
    p_chat.add_argument("--bootstrap", help="Comma-separated bootstrap DHT seeds")

    p_dht = sub.add_parser("dht", help="DHT diagnostics")
    p_dht.add_argument("--port", type=int, help="DHT port")
    p_dht.add_argument("--bootstrap", help="Comma-separated bootstrap DHT seeds")
    p_dht.add_argument("--find", help="Look up a Null ID in the DHT")
    p_dht.add_argument("--advertise", help="Advertise your address")

    args = parser.parse_args()

    # Map commands to handlers
    sync_cmds = {
        "init": cmd_init, "id": cmd_id, "export": cmd_export,
        "import": cmd_import, "contacts": cmd_contacts,
    }
    async_cmds = {
        "p2p": cmd_p2p_listen, "send": cmd_send,
        "chat": cmd_chat, "dht": cmd_dht,
    }

    if args.command in sync_cmds:
        sync_cmds[args.command](args)
    elif args.command in async_cmds:
        asyncio.run(async_cmds[args.command](args))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
