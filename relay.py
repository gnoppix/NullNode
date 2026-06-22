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

import argparse
import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections import defaultdict

import websockets

from protocol import Envelope
from ratelimit import RateLimiter

logger = logging.getLogger("relay")

MAX_QUEUED = 100
QUEUE_TTL = 300
GOSSIP_INTERVAL = 60

# DDoS / abuse hardening
CONN_RATE_MAX = 50
CONN_RATE_WINDOW = 60
MSG_RATE_MAX = 120
MSG_RATE_WINDOW = 60
MAX_MSG_SIZE = 1_048_576
MAX_SESSIONS_PER_NID = 10
MAX_TOTAL_QUEUED = 10_000
CONN_IDLE_TIMEOUT = 300
MAX_PEER_RELAYS = 20

# Remote route expiry
ROUTE_TTL = 1800  # 30 minutes — re-advertise or expire

# Peer relay replay window (seconds)
PEER_CHALLENGE_TTL = 120


class Relay:
    def __init__(
        self,
        relay_url: str = "",
        peer_secret: str = "",
    ):
        self.my_url: str = relay_url
        self.peer_secret: str = peer_secret
        self.sessions: dict[str, set] = defaultdict(set)
        # ws -> registered nid  (each client socket bound to one identity)
        self._ws_nid: dict[object, str] = {}
        self.message_queue: dict[str, list[tuple[float, Envelope]]] = defaultdict(list)
        # remote_routes now stores (relay_url, learned_ts)
        self.remote_routes: dict[str, tuple[str, float]] = {}
        self.peer_relays: dict[str, tuple] = {}
        self._gossip_task: asyncio.Task | None = None
        self._server: asyncio.Server | None = None
        self._conn_limiter = RateLimiter(CONN_RATE_MAX, CONN_RATE_WINDOW)
        self._msg_limiter: dict[str, RateLimiter] = {}
        self._connections: dict[str, int] = defaultdict(int)
        self._total_queued = 0

    # ------------------------------------------------------------------ #
    #  Peer relay authentication helpers                                  #
    # ------------------------------------------------------------------ #

    def _peer_token(self, ts: int) -> str:
        """HMAC-based one-time token for peer relay authentication."""
        mac = hmac.new(
            self.peer_secret.encode(),
            f"peer:{ts}".encode(),
            hashlib.sha256,
        ).hexdigest()[:32]
        return mac

    def _make_challenge(self) -> dict:
        """Produce a challenge dict for incoming peer relay auth."""
        nonce = secrets.token_hex(16)
        ts = int(time.time())
        token = self._peer_token(ts)
        return {"nonce": nonce, "ts": ts, "token": token}

    def _verify_challenge_response(self, challenge: dict, response_token: str) -> bool:
        """Verify that a peer correctly signed our challenge."""
        ts = challenge.get("ts", 0)
        if abs(int(time.time()) - ts) > PEER_CHALLENGE_TTL:
            return False
        expected = self._peer_token(ts)
        return hmac.compare_digest(expected, response_token)

    # ------------------------------------------------------------------ #
    #  Peer relay connection management                                   #
    # ------------------------------------------------------------------ #

    async def _connect_peer_relay(self, peer_url: str):
        if peer_url == self.my_url or peer_url in self.peer_relays:
            return
        try:
            ws = await websockets.connect(peer_url)
            # Perform challenge-response before accepting as peer
            challenge = self._make_challenge()
            auth_env = Envelope(
                type="peer-auth",
                payload={
                    "challenge": challenge,
                    "relay_url": self.my_url,
                },
            )
            await ws.send(auth_env.to_json())
            raw = await asyncio.wait_for(ws.recv(), timeout=10)
            resp = Envelope.from_json(raw)
            if resp.type != "peer-auth-reply":
                logger.warning("peer %s did not complete auth", peer_url)
                await ws.close()
                return
            if not self._verify_challenge_response(
                challenge, resp.payload.get("token", "")
            ):
                logger.warning("peer %s failed challenge-response", peer_url)
                await ws.close(4003, "auth failed")
                return
            self.peer_relays[peer_url] = ws
            logger.info("authenticated peer relay %s", peer_url)
            await self._broadcast_routes()
            asyncio.create_task(self._handle_peer(ws, peer_url))
        except Exception as e:
            logger.warning("failed to peer with %s: %s", peer_url, e)

    async def _handle_peer(self, ws, peer_url: str):
        try:
            async for raw in ws:
                env = Envelope.from_json(raw)
                await self._handle_envelope(env, ws)
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.peer_relays.pop(peer_url, None)
            logger.info("peer relay %s disconnected", peer_url)

    def _register_peer_ws(self, peer_url: str, ws) -> None:
        if peer_url and peer_url not in self.peer_relays:
            self.peer_relays[peer_url] = ws
            logger.info("registered incoming peer relay %s", peer_url)

    # ------------------------------------------------------------------ #
    #  Gossip / routing                                                   #
    # ------------------------------------------------------------------ #

    async def _gossip_loop(self):
        while True:
            await asyncio.sleep(GOSSIP_INTERVAL)

            # Prune expired queued messages
            now = time.time()
            expired_nids = []
            for nid, entries in self.message_queue.items():
                before = len(entries)
                entries[:] = [(ts, e) for ts, e in entries if ts + QUEUE_TTL > now]
                self._total_queued -= before - len(entries)
                if not entries:
                    expired_nids.append(nid)
            for nid in expired_nids:
                del self.message_queue[nid]

            # Prune expired remote routes
            stale_routes = [
                nid
                for nid, (_, learned_at) in self.remote_routes.items()
                if now - learned_at > ROUTE_TTL
            ]
            for nid in stale_routes:
                del self.remote_routes[nid]
                logger.debug("expired route for %s", nid)

            if not self.peer_relays:
                continue
            local_routes = {}
            for nid in self.sessions:
                local_routes[nid] = self.my_url
            ad = Envelope.route_advertise(local_routes)
            for peer_url, pws in list(self.peer_relays.items()):
                try:
                    await pws.send(ad.to_json())
                except Exception:
                    self.peer_relays.pop(peer_url, None)

    async def _broadcast_routes(self):
        if not self.peer_relays:
            return
        local_routes = {nid: self.my_url for nid in self.sessions}
        ad = Envelope.route_advertise(local_routes)
        ad.payload["relay_url"] = self.my_url
        for pws in list(self.peer_relays.values()):
            try:
                await pws.send(ad.to_json())
            except Exception:
                pass

    async def _drain_queue(self, nid: str, relay_url: str):
        pending = self.message_queue.pop(nid, [])
        if not pending:
            return
        self._total_queued -= len(pending)
        for ts, recv_env in pending:
            fwd = Envelope.relay_forward(
                from_relay=self.my_url,
                to_relay=relay_url,
                envelope={
                    "to": nid,
                    "from": recv_env.payload.get("sender", ""),
                    "ciphertext": recv_env.payload.get("ciphertext", ""),
                },
            )
            peer_ws = self.peer_relays.get(relay_url)
            if peer_ws:
                try:
                    await peer_ws.send(fwd.to_json())
                except Exception:
                    self.message_queue[nid].append((ts, recv_env))

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                          #
    # ------------------------------------------------------------------ #

    async def start(self, host: str = "0.0.0.0", port: int = 8765):
        logger.info("relay listening on %s:%s", host, port)
        if not self.my_url:
            self.my_url = f"ws://{host}:{port}"
        self._gossip_task = asyncio.create_task(self._gossip_loop())
        async with websockets.serve(self.handle_client, host, port) as server:
            self._server = server
            await asyncio.Future()

    async def start_background(self, host: str = "0.0.0.0", port: int = 8765):
        self._server = await websockets.serve(
            self.handle_client, host, port,
            max_size=MAX_MSG_SIZE,
            ping_interval=CONN_IDLE_TIMEOUT,
            ping_timeout=30,
        )
        actual_port = self._server.sockets[0].getsockname()[1]
        self.my_url = self.my_url or f"ws://{host}:{actual_port}"
        self._gossip_task = asyncio.create_task(self._gossip_loop())
        self._conn_limiter.start_background_prune()
        logger.info("relay background on %s:%s", host, actual_port)
        return actual_port

    async def stop(self):
        if self._gossip_task:
            self._gossip_task.cancel()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        for pws in self.peer_relays.values():
            await pws.close()
        for sess_set in self.sessions.values():
            for ws in set(sess_set):
                await ws.close()

    async def add_peer(self, peer_url: str):
        await self._connect_peer_relay(peer_url)
        asyncio.create_task(self._peer_reconnect_loop(peer_url))

    async def _peer_reconnect_loop(self, peer_url: str):
        while True:
            await asyncio.sleep(30)
            if peer_url not in self.peer_relays:
                await self._connect_peer_relay(peer_url)

    # ------------------------------------------------------------------ #
    #  Client connection handler                                          #
    # ------------------------------------------------------------------ #

    async def handle_client(self, ws):
        remote = ws.remote_address
        client_ip = remote[0] if remote else "unknown"

        # Connection rate limit per source IP
        if not self._conn_limiter.allow(client_ip):
            logger.warning("rate-limited connection from %s", client_ip)
            await ws.close(4001, "connection rate limit exceeded")
            return

        # Connection count limit per source IP
        self._connections[client_ip] += 1
        if self._connections[client_ip] > 10:
            logger.warning("too many connections from %s", client_ip)
            self._connections[client_ip] -= 1
            await ws.close(4001, "too many connections")
            return

        registered_ids: list[str] = []
        is_peer_relay = False
        # Track whether this ws has been bound to a nid
        bound_nid: str | None = None

        # Per-connection message rate limiter
        self._msg_limiter[client_ip] = self._msg_limiter.get(
            client_ip, RateLimiter(MSG_RATE_MAX, MSG_RATE_WINDOW)
        )

        try:
            async for raw in ws:
                if not self._msg_limiter[client_ip].allow(client_ip):
                    logger.warning("msg rate-limited from %s", client_ip)
                    await ws.send(Envelope.error("rate limited").to_json())
                    continue

                if len(raw) > MAX_MSG_SIZE:
                    await ws.send(Envelope.error("message too large").to_json())
                    continue

                try:
                    env = Envelope.from_json(raw)
                except (ValueError, KeyError) as exc:
                    await ws.send(Envelope.error(f"bad envelope: {exc}").to_json())
                    continue

                # ----- Peer relay handshake (must be first message) -----
                if (
                    env.type == "route-advertise"
                    and not registered_ids
                    and not bound_nid
                ):
                    if len(self.peer_relays) >= MAX_PEER_RELAYS:
                        await ws.send(
                            Envelope.error("max peer relays reached").to_json()
                        )
                        continue
                    is_peer_relay = True
                    peer_url = env.payload.get("relay_url", "")
                    sender_nid = env.payload.get("from", "")
                    peer_id = peer_url or f"{client_ip}:{remote[1]}"
                    ws._peer_url = peer_id
                    self._register_peer_ws(peer_id, ws)
                    await self._handle_envelope(
                        env, ws, remote, registered_ids
                    )
                    await self._handle_peer(ws, peer_id)
                    break

                # ----- Peer auth reply (incoming peer relay) -----
                if env.type == "peer-auth-reply" and not registered_ids and not bound_nid:
                    # This is a reply to our challenge from an incoming connection
                    # that we initiated — handled in _connect_peer_relay.
                    # If we receive it here it means an incoming peer is responding
                    # to a challenge we sent. We handle it inline.
                    challenge = getattr(ws, "_challenge", None)
                    if challenge and self._verify_challenge_response(
                        challenge, env.payload.get("token", "")
                    ):
                        peer_url = env.payload.get("relay_url", "")
                        peer_id = peer_url or f"{client_ip}:{remote[1]}"
                        ws._peer_url = peer_id
                        is_peer_relay = True
                        self._register_peer_ws(peer_id, ws)
                        await self._handle_peer(ws, peer_id)
                    else:
                        await ws.close(4003, "auth failed")
                    break

                # ----- Normal client envelope handling -----
                await self._handle_envelope(
                    env, ws, remote, registered_ids, bound_nid
                )

        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self._connections[client_ip] -= 1
            if self._connections[client_ip] <= 0:
                self._connections.pop(client_ip, None)
                self._msg_limiter.pop(client_ip, None)
            if is_peer_relay:
                peer_id = getattr(ws, "_peer_url", None)
                if peer_id:
                    self.peer_relays.pop(peer_id, None)
            for nid in registered_ids:
                self.sessions[nid].discard(ws)
                if not self.sessions[nid]:
                    del self.sessions[nid]
                self._ws_nid.pop(ws, None)
                logger.info("disconnected %s from %s", nid, remote)

    # ------------------------------------------------------------------ #
    #  Envelope dispatch                                                  #
    # ------------------------------------------------------------------ #

    async def _handle_envelope(
        self,
        env: Envelope,
        ws,
        remote=None,
        registered_ids: list[str] | None = None,
        bound_nid: str | None = None,
    ):
        if env.type == "register":
            nid = env.payload.get("null_id", "")
            if not nid:
                await ws.send(Envelope.error("null_id required").to_json())
                return

            # Verify the client owns this identity:
            # The register envelope must carry a valid GPG signature over
            # the canonical signing payload, and the fingerprint used must
            # hash to the claimed null_id.
            fp = env.payload.get("fingerprint", "")
            sig = env.sig
            if not fp or not sig:
                await ws.send(
                    Envelope.error(
                        "register requires fingerprint and sig"
                    ).to_json()
                )
                return

            # Verify null_id matches fingerprint
            from crypto import null_id as compute_null_id, validate_fingerprint
            if not validate_fingerprint(fp):
                await ws.send(
                    Envelope.error("invalid fingerprint format").to_json()
                )
                return
            expected_nid = compute_null_id(fp)
            if expected_nid != nid:
                await ws.send(
                    Envelope.error(
                        f"null_id mismatch: expected {expected_nid}"
                    ).to_json()
                )
                return

            # Verify signature
            from crypto import verify_signature
            if not verify_signature(env.signing_payload(), sig, fp):
                await ws.send(
                    Envelope.error("signature verification failed").to_json()
                )
                return

            if len(self.sessions.get(nid, set())) >= MAX_SESSIONS_PER_NID:
                await ws.send(
                    Envelope.error(
                        f"max sessions ({MAX_SESSIONS_PER_NID}) reached for {nid}"
                    ).to_json()
                )
                return

            self.sessions[nid].add(ws)
            self._ws_nid[ws] = nid
            if registered_ids is not None:
                registered_ids.append(nid)
            await ws.send(Envelope.registered(nid).to_json())
            logger.info("registered %s from %s", nid, remote)

            # Drain any queued messages
            pending_list = self.message_queue.pop(nid, [])
            self._total_queued -= len(pending_list)
            for ts, pending in pending_list:
                if ts + QUEUE_TTL > env.ts:
                    await ws.send(pending.to_json())

            await self._broadcast_routes()
            return

        # For all message types below, enforce sender authentication
        ws_nid = self._ws_nid.get(ws)
        if not ws_nid:
            await ws.send(
                Envelope.error("not registered — send register first").to_json()
            )
            return

        if env.type == "send":
            recipient = env.payload.get("to", "")
            if not recipient:
                await ws.send(
                    Envelope.error("recipient 'to' required").to_json()
                )
                return

            # Use the authenticated nid as sender, ignore client-supplied from
            sender_nid = ws_nid

            recv_env = Envelope.recv(
                sender=sender_nid,
                ciphertext_b64=env.payload.get("ciphertext", ""),
                ts=env.ts,
            )

            local_recipients = self.sessions.get(recipient, set())

            if local_recipients:
                disconnected = set()
                for rws in local_recipients:
                    try:
                        await rws.send(recv_env.to_json())
                    except websockets.exceptions.ConnectionClosed:
                        disconnected.add(rws)
                local_recipients -= disconnected
                if not local_recipients:
                    del self.sessions[recipient]
                    self.message_queue[recipient].append((env.ts, recv_env))
                await ws.send(Envelope.ack(env.msg_id).to_json())

            elif recipient in self.remote_routes:
                relay_url, _ = self.remote_routes[recipient]
                fwd = Envelope.relay_forward(
                    from_relay=self.my_url,
                    to_relay=relay_url,
                    envelope={
                        "to": recipient,
                        "from": sender_nid,
                        "ciphertext": env.payload.get("ciphertext", ""),
                    },
                )
                peer_ws = self.peer_relays.get(relay_url)
                if peer_ws:
                    try:
                        await peer_ws.send(fwd.to_json())
                        await ws.send(Envelope.ack(env.msg_id).to_json())
                    except Exception:
                        self.peer_relays.pop(relay_url, None)
                        self.message_queue[recipient].append((env.ts, recv_env))
                        await ws.send(Envelope.ack(env.msg_id).to_json())
                else:
                    self.message_queue[recipient].append((env.ts, recv_env))
                    await ws.send(Envelope.ack(env.msg_id).to_json())
                    for peer_url, pws in self.peer_relays.items():
                        try:
                            await pws.send(
                                Envelope.who_has(recipient, self.my_url).to_json()
                            )
                        except Exception:
                            pass
            else:
                if self._total_queued >= MAX_TOTAL_QUEUED:
                    await ws.send(Envelope.error("server queue full").to_json())
                    return
                queue = self.message_queue[recipient]
                queue.append((env.ts, recv_env))
                self._total_queued += 1
                if len(queue) > MAX_QUEUED:
                    removed = queue.pop(0)
                    self._total_queued -= 1
                await ws.send(Envelope.ack(env.msg_id).to_json())

        elif env.type == "relay-forward":
            # Only accept relay-forward from authenticated peer relays
            peer_id = getattr(ws, "_peer_url", None)
            if not peer_id or peer_id not in self.peer_relays:
                logger.warning("relay-forward from non-peer ignored")
                return

            payload = env.payload.get("envelope", {})
            to_nid = payload.get("to", "")
            inner_from = payload.get("from", "")

            # Validate: the inner sender must be registered on the
            # originating relay.  We cannot fully verify this across
            # federation, but we can at least check the format.
            if not to_nid or not inner_from:
                logger.warning("relay-forward with empty to/from ignored")
                return

            recv_env = Envelope.recv(
                sender=inner_from,
                ciphertext_b64=payload.get("ciphertext", ""),
                ts=env.ts,
            )
            local_recipients = self.sessions.get(to_nid, set())
            if local_recipients:
                for rws in local_recipients:
                    try:
                        await rws.send(recv_env.to_json())
                    except Exception:
                        pass
            else:
                self.message_queue[to_nid].append((env.ts, recv_env))

            from_relay = env.payload.get("from_relay", "")
            if from_relay and to_nid:
                self.remote_routes[to_nid] = (from_relay, time.time())

        elif env.type == "route-advertise":
            routes = env.payload.get("routes", {})
            now = time.time()
            for nid, relay_url in routes.items():
                if nid not in self.sessions and nid not in self.remote_routes:
                    self.remote_routes[nid] = (relay_url, now)
                    await self._drain_queue(nid, relay_url)

        elif env.type == "who-has":
            nid = env.payload.get("null_id", "")
            asker = env.payload.get("asker_relay", "")
            if nid in self.sessions:
                found = Envelope.route_found(nid, self.my_url, asker)
                for peer_url, pws in self.peer_relays.items():
                    if peer_url == asker:
                        try:
                            await pws.send(found.to_json())
                        except Exception:
                            pass

        elif env.type == "route-found":
            nid = env.payload.get("null_id", "")
            relay_url = env.payload.get("relay_url", "")
            asker = env.payload.get("asker_relay", "")
            if asker == self.my_url and nid:
                self.remote_routes[nid] = (relay_url, time.time())
                logger.info("route learned: %s → %s", nid, relay_url)
                await self._drain_queue(nid, relay_url)

        elif env.type == "p2p-direct":
            sender = env.payload.get("from", "")
            ct = env.payload.get("ciphertext", "")
            if registered_ids:
                for nid in registered_ids:
                    recv = Envelope.recv(sender, ct, env.ts)
                    try:
                        await ws.send(recv.to_json())
                    except Exception:
                        pass

        elif env.type == "online":
            if registered_ids:
                for nid in registered_ids:
                    await ws.send(Envelope.online(nid).to_json())


def main():
    parser = argparse.ArgumentParser(description="NullNode Relay")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--peer", action="append", help="peer relay URLs to federate with"
    )
    parser.add_argument("--url", default="", help="public URL of this relay")
    parser.add_argument(
        "--peer-secret",
        default="",
        help="shared secret for peer relay authentication (required for federation)",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    relay = Relay(
        relay_url=args.url or f"ws://{args.host}:{args.port}",
        peer_secret=args.peer_secret,
    )

    async def run():
        if args.peer:
            for p in args.peer:
                await relay.add_peer(p)
        await relay.start(args.host, args.port)

    asyncio.run(run())


if __name__ == "__main__":
    main()
