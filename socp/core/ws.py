
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import websockets
from websockets.exceptions import ConnectionClosed

from . import presence, proto, router


log = logging.getLogger("socp.ws")


class Link:
    def __init__(self, websocket: websockets.WebSocketServerProtocol) -> None:
        self.ws = websocket
        self.identity: Optional[str] = None
        self.kind: Optional[str] = None  # "user" or "server"

    async def send(self, frame: dict) -> None:
        await self.ws.send(json.dumps(frame))

    async def close(self, code: int = 1000, reason: str | None = None) -> None:
        await self.ws.close(code=code, reason=reason)

    async def recv_text(self) -> Optional[str]:
        message = await self.ws.recv()
        if isinstance(message, str):
            return message
        log.warning("Binary frame from %s rejected", self.identity or "unknown")
        await self.close(code=1003, reason="binary frames not supported")
        return None


async def serve(host: str, port: int, router_state: router.Router) -> None:
    async def handler(websocket: websockets.WebSocketServerProtocol) -> None:
        link = Link(websocket)
        try:
            await _handle_connection(link, router_state)
        except ConnectionClosed:
            pass
        except Exception:  # pragma: no cover - defensive logging only
            log.exception("Unhandled error while processing websocket connection")
            await link.close(code=1011, reason="internal error")

    async with websockets.serve(handler, host, port):
        await asyncio.Future()


async def _handle_connection(link: Link, router_state: router.Router) -> None:
    hello_raw = await link.recv_text()
    if hello_raw is None:
        return

    try:
        hello = proto.parse_envelope(hello_raw)
    except proto.FrameValidationError as exc:
        log.warning("Invalid hello frame: %s", exc)
        await link.close(code=1003, reason="invalid hello")
        return

    if hello.type == "USER_HELLO":
        await _accept_user(link, router_state, hello)
    elif hello.type.startswith("SERVER_HELLO"):
        await _accept_server(link, router_state, hello)
    else:
        await link.send(proto.make_error(router_state.server_id, hello.from_, "UNKNOWN_TYPE"))
        await link.close(code=1008, reason="unexpected hello type")


async def _accept_user(link: Link, router_state: router.Router, hello: proto.Envelope) -> None:
    user_id = hello.from_
    if user_id in router_state.local_users:
        await link.send(proto.make_error(router_state.server_id, user_id, "NAME_IN_USE"))
        await link.close(code=1008, reason="user already connected")
        return

    link.identity = user_id
    link.kind = "user"
    router_state.register_local_user(user_id, link)
    try:
        await presence.on_user_local_join(user_id, hello.payload)
    except Exception:  # pragma: no cover - presence broadcast best effort
        log.exception("Presence join hook failed for %s", user_id)

    await link.send(proto.make_ack(router_state.server_id, user_id, hello.type, hello.ts))

    try:
        async for raw in link.ws:
            if not isinstance(raw, str):
                log.warning("Binary frame from user %s", user_id)
                await link.close(code=1003, reason="binary frames not supported")
                break
            if not await _process_frame(router_state, link, raw):
                break
    finally:
        router_state.unregister_local_user(user_id)
        try:
            await presence.on_user_local_leave(user_id)
        except Exception:  # pragma: no cover - presence broadcast best effort
            log.exception("Presence leave hook failed for %s", user_id)


async def _accept_server(link: Link, router_state: router.Router, hello: proto.Envelope) -> None:
    server_id = hello.from_
    link.identity = server_id
    link.kind = "server"
    advertised_users = hello.payload.get("users") if isinstance(hello.payload, dict) else None
    if server_id in router_state.server_links:
        await link.close(code=1008, reason="server already linked")
        return

    router_state.register_server_link(server_id, link, advertised_users or None)
    await link.send(proto.make_ack(router_state.server_id, server_id, hello.type, hello.ts))

    try:
        async for raw in link.ws:
            if not isinstance(raw, str):
                log.warning("Binary frame from server %s", server_id)
                await link.close(code=1003, reason="binary frames not supported")
                break
            if not await _process_frame(router_state, link, raw):
                break
    finally:
        router_state.unregister_server_link(server_id)


async def _process_frame(router_state: router.Router, link: Link, frame_raw: str) -> bool:
    try:
        envelope = proto.parse_envelope(frame_raw)
    except proto.FrameValidationError as exc:
        log.warning("Invalid frame from %s: %s", link.identity or "unknown", exc)
        await link.close(code=1003, reason="invalid frame")
        return False

    decision = router_state.route(envelope)

    if decision.action == "drop":
        log.debug("Dropped duplicate frame %s→%s", envelope.from_, envelope.to)
        return True

    if decision.action == "deliver_local":
        target_link = router_state.local_users.get(decision.target or "")
        if not target_link:
            await link.send(proto.make_error(router_state.server_id, link.identity or "", "USER_NOT_FOUND"))
            return True
        deliver = proto.build_frame("USER_DELIVER", envelope.from_, envelope.to, envelope.payload)
        await target_link.send(deliver)
        await link.send(
            proto.make_ack(router_state.server_id, link.identity or envelope.from_, envelope.type, envelope.ts)
        )
        return True

    if decision.action == "forward":
        server_id = decision.target
        server_link = router_state.server_links.get(server_id or "")
        if not server_link:
            await link.send(proto.make_error(router_state.server_id, link.identity or "", "USER_NOT_FOUND"))
            return True
        forward = proto.build_frame("SERVER_DELIVER", envelope.from_, envelope.to, envelope.payload)
        await server_link.send(forward)
        await link.send(
            proto.make_ack(router_state.server_id, link.identity or envelope.from_, envelope.type, envelope.ts)
        )
        return True

    if decision.action == "error":
        await link.send(proto.make_error(router_state.server_id, link.identity or envelope.from_, decision.code or "USER_NOT_FOUND"))
        return True

    log.error("Unhandled routing action %s", decision.action)
    await link.close(code=1011, reason="routing error")
    return False
