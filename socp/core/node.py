from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

import orjson
import websockets

from socp.core import crypto, proto, router, store
from socp.core.config import ServerConfig
from socp.core.ws import Link

log = logging.getLogger("socp.node")


@dataclass(slots=True)
class ClientSession:
    user_id: str
    link: Link
    sign_pub: bytes
    enc_pub: bytes
    meta: Dict[str, object]


@dataclass(slots=True)
class ServerLink:
    server_id: str
    link: Link
    pubkey: bytes
    address: tuple[str, int]
    task: asyncio.Task
    last_seen: float = field(default_factory=lambda: time.time())


@dataclass(slots=True)
class ConnectionContext:
    websocket: websockets.WebSocketClientProtocol
    link: Link
    task: Optional[asyncio.Task] = None
    kind: str = "unknown"
    peer_id: Optional[str] = None
    pubkey: Optional[bytes] = None
    address: Optional[tuple[str, int]] = None
    outbound: bool = False


class ServerRuntime:
    """Runtime for a SOCP v1.3 server."""

    def __init__(self, config: ServerConfig):
        self.config = config
        self.server_id = config.server_id
        self.keys: Optional[crypto.RSAKeyPair] = None
        self._server: Optional[websockets.server.Serve] = None
        self._running = False
        self._connections: set[asyncio.Task] = set()
        self._heartbeat_task: Optional[asyncio.Task] = None

        self.local_users: Dict[str, ClientSession] = {}
        self.user_locations: Dict[str, str] = {}
        self.directory: Dict[str, Dict[str, object]] = {}
        self.server_links: Dict[str, ServerLink] = {}
        self.server_addrs: Dict[str, tuple[str, int]] = {}
        self.server_pubkeys: Dict[str, bytes] = {}
        self.duplicate_tracker = router.DuplicateTracker()
        self.public_channel_key = os.urandom(32)
        self.public_channel_version = 1

    async def start(self) -> None:
        if self._running:
            return
        log.info("Starting SOCP runtime %s", self.server_id)
        self.keys = crypto.ensure_rsa_pair(self.config.private_key_path, self.config.public_key_path)
        await store.init(str(self.config.db_path))
        await store.ensure_public_group()

        self._server = await websockets.serve(self._accept_connection, self.config.listen_host, self.config.listen_port)
        self._running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        log.info("Listening on %s:%s", self.config.listen_host, self.config.listen_port)

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        log.info("Stopping SOCP runtime %s", self.server_id)
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._heartbeat_task
            self._heartbeat_task = None
        for link in list(self.server_links.values()):
            with contextlib.suppress(Exception):
                await link.link.close()
        for task in list(self._connections):
            task.cancel()
        for task in list(self._connections):
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._connections.clear()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        await store.close()
        self.local_users.clear()
        self.user_locations.clear()
        self.directory.clear()
        self.server_links.clear()
        self.server_addrs.clear()
        self.server_pubkeys.clear()

    async def _accept_connection(self, websocket: websockets.WebSocketServerProtocol) -> None:
        link = Link(websocket)
        task = asyncio.current_task()
        assert task is not None
        ctx = ConnectionContext(websocket=websocket, link=link, task=task)
        self._connections.add(task)
        task.add_done_callback(self._connections.discard)
        try:
            await self._connection_loop(ctx)
        finally:
            await self._on_connection_closed(ctx)

    async def _connection_loop(self, ctx: ConnectionContext) -> None:
        ctx.task = asyncio.current_task()
        if ctx.outbound:
            await self._send_server_hello(ctx)
        try:
            async for raw in ctx.websocket:
                try:
                    data = orjson.loads(raw)
                    envelope = proto.Envelope(**data)
                except Exception as exc:  # pragma: no cover - defensive
                    log.warning("Malformed frame: %s", exc)
                    continue
                await self._dispatch(ctx, envelope)
        except websockets.ConnectionClosed:
            pass
        finally:
            if ctx.outbound:
                await self._on_connection_closed(ctx)

    async def _dispatch(self, ctx: ConnectionContext, envelope: proto.Envelope) -> None:
        if ctx.kind == "unknown":
            if envelope.type == "USER_HELLO":
                await self._handle_user_hello(ctx, envelope)
                return
            if envelope.type == "SERVER_HELLO_JOIN":
                await self._handle_server_hello(ctx, envelope)
                return
            if envelope.type == "SERVER_WELCOME":
                await self._handle_server_welcome(ctx, envelope)
                return
        if ctx.kind == "client":
            session = self.local_users.get(ctx.peer_id or "")
            if session is None:
                return
            if envelope.type != "HEARTBEAT" and not proto.verify_envelope(envelope, session.sign_pub):
                await self._send_error(session.link, session.user_id, "INVALID_SIG", "signature failure")
                return
            await self._handle_client_frame(session, envelope)
            return
        if ctx.kind == "server":
            link = self.server_links.get(ctx.peer_id or "")
            if link is None:
                return
            if not proto.verify_envelope(envelope, link.pubkey):
                log.warning("Signature verification failed for server %s", ctx.peer_id)
                return
            link.last_seen = time.time()
            await self._handle_server_frame(ctx, envelope)
            return
        log.debug("Ignoring frame %s from unknown context", envelope.type)

    async def _handle_client_frame(self, session: ClientSession, envelope: proto.Envelope) -> None:
        typ = envelope.type
        if typ == "LIST_USERS":
            await self._send_user_list(session)
        elif typ == "MSG_DIRECT":
            await self._handle_direct_message(envelope)
        elif typ in {"FILE_START", "FILE_CHUNK", "FILE_END"}:
            await self._handle_file_frame(envelope)
        elif typ == "MSG_PUBLIC_CHANNEL":
            await self._handle_public_message(session.user_id, envelope)
        else:
            log.debug("Unhandled client frame %s", typ)

    async def _handle_server_frame(self, ctx: ConnectionContext, envelope: proto.Envelope) -> None:
        typ = envelope.type
        if typ == "SERVER_WELCOME":
            await self._handle_server_welcome(ctx, envelope)
        elif typ == "USER_ADVERTISE":
            await self._handle_user_advertise(envelope)
        elif typ == "USER_REMOVE":
            await self._handle_user_remove(envelope)
        elif typ == "SERVER_DELIVER":
            await self._handle_server_deliver(envelope)
        elif typ == "HEARTBEAT":
            link = self.server_links.get(ctx.peer_id or "")
            if link:
                link.last_seen = time.time()
        else:
            log.debug("Unhandled server frame %s", typ)

    async def _handle_user_hello(self, ctx: ConnectionContext, envelope: proto.Envelope) -> None:
        payload = envelope.payload
        user_id = payload.get("client")
        pub_b64 = payload.get("pubkey")
        enc_b64 = payload.get("enc_pubkey")
        meta = payload.get("meta") or {}
        if not user_id or not pub_b64 or not enc_b64:
            await ctx.link.close()
            return
        if user_id in self.local_users:
            await self._send_error(ctx.link, user_id, "NAME_IN_USE", "user already connected")
            await ctx.link.close()
            return
        try:
            sign_pub = crypto.b64url_decode(pub_b64)
            enc_pub = crypto.b64url_decode(enc_b64)
        except ValueError:
            await self._send_error(ctx.link, "*", "BAD_KEY", "invalid key encoding")
            await ctx.link.close()
            return
        if not crypto.accept_pubkey(sign_pub) or not crypto.accept_pubkey(enc_pub):
            await self._send_error(ctx.link, "*", "BAD_KEY", "weak key rejected")
            await ctx.link.close()
            return
        session = ClientSession(user_id=user_id, link=ctx.link, sign_pub=sign_pub, enc_pub=enc_pub, meta=meta)
        self.local_users[user_id] = session
        self.user_locations[user_id] = "local"
        self.directory[user_id] = {
            "user_id": user_id,
            "pubkey": pub_b64,
            "enc_pubkey": enc_b64,
            "meta": meta,
            "server_id": self.server_id,
        }
        ctx.kind = "client"
        ctx.peer_id = user_id
        try:
            await store.upsert_user(user_id, sign_pub, meta)
        except Exception as exc:  # pragma: no cover - db failures shouldn't break tests
            log.debug("DB error on upsert: %s", exc)
        await self._send_ack(session.link, user_id, "USER_HELLO")
        await self._provision_public_channel(session)
        await self._broadcast_user_advertise(user_id, meta)

    async def _send_ack(self, link: Link, target: str, ref: str) -> None:
        envelope = proto.build_envelope("ACK", self.server_id, target, {"msg_ref": ref})
        assert self.keys is not None
        proto.sign_envelope(envelope, self.keys.private_pem)
        await link.send(proto.envelope_to_dict(envelope))

    async def _send_error(self, link: Link, target: str, code: str, detail: str) -> None:
        envelope = proto.build_envelope("ERROR", self.server_id, target, {"code": code, "detail": detail})
        assert self.keys is not None
        proto.sign_envelope(envelope, self.keys.private_pem)
        await link.send(proto.envelope_to_dict(envelope))

    async def _send_error_to_user(self, user_id: str, code: str, detail: str) -> None:
        session = self.local_users.get(user_id)
        if not session:
            return
        await self._send_error(session.link, user_id, code, detail)

    async def _send_user_list(self, session: ClientSession) -> None:
        users = []
        for entry in self.directory.values():
            users.append({
                "user_id": entry.get("user_id"),
                "pubkey": entry.get("pubkey"),
                "enc_pubkey": entry.get("enc_pubkey"),
                "meta": entry.get("meta", {}),
                "server_id": entry.get("server_id"),
            })
        payload = {"users": sorted(users, key=lambda item: item.get("user_id") or "")}
        envelope = proto.build_envelope("LIST_USERS_RESULT", self.server_id, session.user_id, payload)
        assert self.keys is not None
        proto.sign_envelope(envelope, self.keys.private_pem)
        await session.link.send(proto.envelope_to_dict(envelope))

    async def _handle_direct_message(self, envelope: proto.Envelope) -> None:
        payload = envelope.payload
        target = payload.get("to")
        if not target:
            await self._send_error_to_user(envelope.from_, "UNKNOWN_TYPE", "missing target")
            return
        frame = proto.envelope_to_dict(envelope)
        decision, dest = router.route_to_user(target, frame, self.local_users, self.user_locations, self.duplicate_tracker)
        if decision == "deliver_local":
            log.debug("Delivering local DM from %s to %s", envelope.from_, target)
            await self._deliver_user_message(target, envelope.from_, payload)
        elif decision == "forward":
            log.debug("Forwarding DM from %s to %s via %s", envelope.from_, target, dest)
            await self._forward_server_deliver(dest, target, envelope.from_, payload, "USER_DELIVER")
        else:
            if dest == "USER_NOT_FOUND":
                await self._send_error_to_user(envelope.from_, "USER_NOT_FOUND", "unknown user")
            else:
                await self._send_error_to_user(envelope.from_, "TIMEOUT", dest)

    async def _handle_file_frame(self, envelope: proto.Envelope) -> None:
        payload = envelope.payload
        target = payload.get("to")
        if not target:
            await self._send_error_to_user(envelope.from_, "UNKNOWN_TYPE", "missing target")
            return
        frame = proto.envelope_to_dict(envelope)
        decision, dest = router.route_to_user(target, frame, self.local_users, self.user_locations, self.duplicate_tracker)
        if decision == "deliver_local":
            log.debug("Delivering local file frame %s from %s to %s", envelope.type, envelope.from_, target)
            await self._deliver_file_frame(target, envelope.from_, envelope.type, payload)
        elif decision == "forward":
            log.debug("Forwarding file frame %s from %s to %s via %s", envelope.type, envelope.from_, target, dest)
            await self._forward_server_deliver(dest, target, envelope.from_, payload, envelope.type)
        else:
            if dest == "USER_NOT_FOUND":
                await self._send_error_to_user(envelope.from_, "USER_NOT_FOUND", "unknown user")
            else:
                await self._send_error_to_user(envelope.from_, "TIMEOUT", dest)

    async def _deliver_user_message(self, target: str, sender: str, payload: Dict[str, object]) -> None:
        session = self.local_users.get(target)
        if not session:
            return
        deliver_payload = {
            "from": sender,
            "ciphertext": payload.get("ciphertext"),
            "sender_pub": payload.get("sender_pub"),
            "content_sig": payload.get("content_sig"),
            "ts": payload.get("ts"),
        }
        envelope = proto.build_envelope("USER_DELIVER", self.server_id, target, deliver_payload)
        assert self.keys is not None
        proto.sign_envelope(envelope, self.keys.private_pem)
        await session.link.send(proto.envelope_to_dict(envelope))

    async def _deliver_file_frame(self, target: str, sender: str, kind: str, payload: Dict[str, object]) -> None:
        session = self.local_users.get(target)
        if not session:
            return
        deliver_payload = dict(payload)
        deliver_payload["from"] = sender
        envelope = proto.build_envelope(kind, self.server_id, target, deliver_payload)
        assert self.keys is not None
        proto.sign_envelope(envelope, self.keys.private_pem)
        await session.link.send(proto.envelope_to_dict(envelope))

    async def _forward_server_deliver(
        self,
        server_id: str,
        target: str,
        sender: str,
        payload: Dict[str, object],
        kind: str,
    ) -> None:
        link = self.server_links.get(server_id)
        if not link:
            log.debug("No link for server %s", server_id)
            return
        content = dict(payload)
        hops = int(content.get("hops", 0)) + 1
        content["hops"] = hops
        log.debug("Forwarding to server %s for user %s (kind=%s, hops=%s)", server_id, target, kind, hops)
        forward_payload = {
            "user_id": target,
            "sender": sender,
            "content": content,
            "hops": hops,
            "kind": kind,
        }
        envelope = proto.build_envelope("SERVER_DELIVER", self.server_id, server_id, forward_payload)
        assert self.keys is not None
        proto.sign_envelope(envelope, self.keys.private_pem)
        await link.link.send(proto.envelope_to_dict(envelope))

    async def _handle_server_deliver(self, envelope: proto.Envelope) -> None:
        payload = envelope.payload
        target = payload.get("user_id")
        content = dict(payload.get("content", {}))
        if not target or not content:
            return
        sender = payload.get("sender") or envelope.from_
        hops = int(payload.get("hops", content.get("hops", 0)))
        content["hops"] = hops
        content.setdefault("to", target)
        frame = {
            "ts": envelope.ts,
            "from": sender,
            "to": target,
            "payload": content,
        }
        decision, dest = router.route_to_user(target, frame, self.local_users, self.user_locations, self.duplicate_tracker)
        if decision == "deliver_local":
            if payload.get("kind") == "USER_DELIVER":
                log.debug("Server deliver local DM to %s from %s", target, sender)
                await self._deliver_user_message(target, sender, content)
            else:
                log.debug("Server deliver local %s to %s from %s", payload.get("kind"), target, sender)
                await self._deliver_file_frame(target, sender, payload.get("kind", "FILE_CHUNK"), content)
        elif decision == "forward":
            log.debug("Server forward %s for %s via %s", payload.get("kind"), target, dest)
            await self._forward_server_deliver(dest, target, sender, content, payload.get("kind", "USER_DELIVER"))

    async def _handle_public_message(self, sender: str, envelope: proto.Envelope) -> None:
        payload = envelope.payload
        deliver_payload = {
            "from": sender,
            "ciphertext": payload.get("ciphertext"),
            "sender_pub": payload.get("sender_pub"),
            "content_sig": payload.get("content_sig"),
            "ts": payload.get("ts"),
        }
        for user_id, session in self.local_users.items():
            if user_id == sender:
                continue
            env = proto.build_envelope("PUBLIC_DELIVER", self.server_id, user_id, deliver_payload)
            assert self.keys is not None
            proto.sign_envelope(env, self.keys.private_pem)
            await session.link.send(proto.envelope_to_dict(env))

    async def _provision_public_channel(self, session: ClientSession) -> None:
        wrapped = crypto.rsa_encrypt_oaep(session.enc_pub, self.public_channel_key)
        payload = {
            "group_id": "public",
            "version": self.public_channel_version,
            "member_id": session.user_id,
            "wrapped_key": crypto.b64url(wrapped),
        }
        envelope = proto.build_envelope("PUBLIC_CHANNEL_ADD", self.server_id, session.user_id, payload)
        assert self.keys is not None
        proto.sign_envelope(envelope, self.keys.private_pem)
        await session.link.send(proto.envelope_to_dict(envelope))
        try:
            await store.add_public_member(session.user_id, payload["wrapped_key"])
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("DB error on add_public_member: %s", exc)

    async def _broadcast_user_advertise(self, user_id: str, meta: Dict[str, object]) -> None:
        if not self.server_links:
            return
        entry = self.directory[user_id]
        payload = {
            "user_id": user_id,
            "server_id": self.server_id,
            "pubkey": entry.get("pubkey"),
            "enc_pubkey": entry.get("enc_pubkey"),
            "meta": meta,
            "hops": 0,
        }
        for server_id in list(self.server_links.keys()):
            await self._send_user_advertise(server_id, payload)

    async def _send_user_advertise(self, server_id: str, payload: Dict[str, object]) -> None:
        link = self.server_links.get(server_id)
        if not link:
            return
        advert = dict(payload)
        advert["hops"] = int(advert.get("hops", 0)) + 1
        envelope = proto.build_envelope("USER_ADVERTISE", self.server_id, server_id, advert)
        assert self.keys is not None
        proto.sign_envelope(envelope, self.keys.private_pem)
        await link.link.send(proto.envelope_to_dict(envelope))

    async def _handle_user_advertise(self, envelope: proto.Envelope) -> None:
        payload = envelope.payload
        user_id = payload.get("user_id")
        server_id = payload.get("server_id") or envelope.from_
        if not user_id or not server_id:
            return
        hops = int(payload.get("hops", 0)) + 1
        if self.user_locations.get(user_id) == server_id:
            return
        self.user_locations[user_id] = server_id
        self.directory[user_id] = {
            "user_id": user_id,
            "pubkey": payload.get("pubkey"),
            "enc_pubkey": payload.get("enc_pubkey"),
            "meta": payload.get("meta", {}),
            "server_id": server_id,
        }
        for other_id in list(self.server_links.keys()):
            if other_id == envelope.from_:
                continue
            forward = dict(payload)
            forward["hops"] = hops
            await self._send_user_advertise(other_id, forward)

    async def _handle_user_remove(self, envelope: proto.Envelope) -> None:
        payload = envelope.payload
        user_id = payload.get("user_id")
        if not user_id:
            return
        if user_id in self.directory:
            self.directory.pop(user_id, None)
        if self.user_locations.get(user_id) != "local":
            self.user_locations.pop(user_id, None)

    async def _handle_server_hello(self, ctx: ConnectionContext, envelope: proto.Envelope) -> None:
        payload = envelope.payload
        remote_id = payload.get("server_id") or envelope.from_
        pub_b64 = payload.get("pubkey")
        host = payload.get("host", self.config.listen_host)
        port = int(payload.get("port", self.config.listen_port))
        if not remote_id or not pub_b64:
            await ctx.link.close()
            return
        try:
            pubkey = crypto.b64url_decode(pub_b64)
        except ValueError:
            await ctx.link.close()
            return
        ctx.kind = "server"
        ctx.peer_id = remote_id
        ctx.pubkey = pubkey
        ctx.address = (host, port)
        if not proto.verify_envelope(envelope, pubkey):
            await ctx.link.close()
            return
        self._register_server_link(ctx, pubkey)
        self.server_addrs[remote_id] = (host, port)
        self.server_pubkeys[remote_id] = pubkey
        clients = [entry for entry in self.directory.values() if entry.get("server_id") == self.server_id]
        response = {
            "assigned_id": self.server_id,
            "pubkey": crypto.b64url(self.keys.public_pem) if self.keys else "",
            "host": self.config.listen_host,
            "port": self.config.listen_port,
            "clients": clients,
        }
        await self._send_server_welcome(remote_id, response)
        await self._broadcast_local_users_to(remote_id)

    async def _handle_server_welcome(self, ctx: ConnectionContext, envelope: proto.Envelope) -> None:
        payload = envelope.payload
        remote_id = envelope.from_
        pub_b64 = payload.get("pubkey")
        if not pub_b64:
            return
        try:
            pubkey = crypto.b64url_decode(pub_b64)
        except ValueError:
            return
        if not proto.verify_envelope(envelope, pubkey):
            return
        ctx.kind = "server"
        ctx.peer_id = remote_id
        ctx.pubkey = pubkey
        ctx.address = (payload.get("host", self.config.listen_host), int(payload.get("port", self.config.listen_port)))
        self._register_server_link(ctx, pubkey)
        self.server_addrs[remote_id] = ctx.address
        self.server_pubkeys[remote_id] = pubkey
        for entry in payload.get("clients", []):
            user_id = entry.get("user_id")
            if not user_id:
                continue
            self.user_locations[user_id] = remote_id
            self.directory[user_id] = {
                "user_id": user_id,
                "pubkey": entry.get("pubkey"),
                "enc_pubkey": entry.get("enc_pubkey"),
                "meta": entry.get("meta", {}),
                "server_id": remote_id,
            }
        await self._broadcast_local_users_to(remote_id)

    def _register_server_link(self, ctx: ConnectionContext, pubkey: bytes) -> None:
        if ctx.peer_id is None:
            return
        if ctx.peer_id in self.server_links:
            existing = self.server_links[ctx.peer_id]
            if existing.link.ws is ctx.link.ws:
                return
            if not getattr(existing.link.ws, "closed", False):
                # Prefer the existing connection to avoid thrashing when both sides dial.
                asyncio.create_task(ctx.link.close())
                return
        link = ServerLink(server_id=ctx.peer_id, link=ctx.link, pubkey=pubkey, address=ctx.address or ("", 0), task=ctx.task)
        self.server_links[ctx.peer_id] = link

    async def _send_server_welcome(self, server_id: str, payload: Dict[str, object]) -> None:
        link = self.server_links.get(server_id)
        if not link:
            return
        envelope = proto.build_envelope("SERVER_WELCOME", self.server_id, server_id, payload)
        assert self.keys is not None
        proto.sign_envelope(envelope, self.keys.private_pem)
        await link.link.send(proto.envelope_to_dict(envelope))

    async def _broadcast_local_users_to(self, server_id: str) -> None:
        for user_id, entry in self.directory.items():
            if entry.get("server_id") != self.server_id:
                continue
            payload = {
                "user_id": user_id,
                "server_id": self.server_id,
                "pubkey": entry.get("pubkey"),
                "enc_pubkey": entry.get("enc_pubkey"),
                "meta": entry.get("meta", {}),
                "hops": 0,
            }
            await self._send_user_advertise(server_id, payload)

    async def _on_connection_closed(self, ctx: ConnectionContext) -> None:
        if ctx.kind == "client" and ctx.peer_id:
            user_id = ctx.peer_id
            self.local_users.pop(user_id, None)
            if self.user_locations.get(user_id) == "local":
                self.user_locations.pop(user_id, None)
            self.directory.pop(user_id, None)
            payload = {"user_id": user_id, "server_id": self.server_id}
            for server_id in list(self.server_links.keys()):
                await self._send_user_remove(server_id, payload)
        elif ctx.kind == "server" and ctx.peer_id:
            server_id = ctx.peer_id
            link = self.server_links.get(server_id)
            if link and link.link.ws is ctx.link.ws:
                self.server_links.pop(server_id, None)
                self.server_pubkeys.pop(server_id, None)
                self.server_addrs.pop(server_id, None)

    async def _send_user_remove(self, server_id: str, payload: Dict[str, object]) -> None:
        link = self.server_links.get(server_id)
        if not link:
            return
        envelope = proto.build_envelope("USER_REMOVE", self.server_id, server_id, payload)
        assert self.keys is not None
        proto.sign_envelope(envelope, self.keys.private_pem)
        await link.link.send(proto.envelope_to_dict(envelope))

    async def _send_server_hello(self, ctx: ConnectionContext) -> None:
        if self.keys is None:
            return
        payload = {
            "server_id": self.server_id,
            "host": self.config.listen_host,
            "port": self.config.listen_port,
            "pubkey": crypto.b64url(self.keys.public_pem),
        }
        envelope = proto.build_envelope("SERVER_HELLO_JOIN", self.server_id, "*", payload)
        proto.sign_envelope(envelope, self.keys.private_pem)
        await ctx.link.send(proto.envelope_to_dict(envelope))

    async def _heartbeat_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self.config.heartbeat_secs)
                now = time.time()
                for server_id, link in list(self.server_links.items()):
                    if now - link.last_seen > self.config.dead_after_secs:
                        log.info("Server %s considered dead", server_id)
                        self.server_links.pop(server_id, None)
                        with contextlib.suppress(Exception):
                            await link.link.close()
                        continue
                    await self._send_heartbeat(server_id)
        except asyncio.CancelledError:  # pragma: no cover - shutdown
            pass

    async def _send_heartbeat(self, server_id: str) -> None:
        link = self.server_links.get(server_id)
        if not link:
            return
        envelope = proto.build_envelope("HEARTBEAT", self.server_id, server_id, {})
        assert self.keys is not None
        proto.sign_envelope(envelope, self.keys.private_pem)
        await link.link.send(proto.envelope_to_dict(envelope))

    async def _dial_server(self, host: str, port: int) -> None:
        websocket = await websockets.connect(f"ws://{host}:{port}")
        link = Link(websocket)
        ctx = ConnectionContext(websocket=websocket, link=link, outbound=True)
        task = asyncio.create_task(self._connection_loop(ctx))
        ctx.task = task
        self._connections.add(task)
        task.add_done_callback(self._connections.discard)
