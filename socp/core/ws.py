from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

import orjson
import websockets

log = logging.getLogger("socp.ws")


class Link:
    """Lightweight wrapper around a WebSocket connection."""

    def __init__(self, websocket: websockets.WebSocketClientProtocol):
        self.ws = websocket
        self._lock = asyncio.Lock()

    async def send(self, frame: dict) -> None:
        data = orjson.dumps(frame).decode("utf-8")
        async with self._lock:
            await self.ws.send(data)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        await self.ws.close(code=code, reason=reason)


async def serve(
    host: str,
    port: int,
    handler: Callable[[websockets.WebSocketServerProtocol], Awaitable[None]],
) -> websockets.server.Serve:
    """Start a websocket server bound to *host*:*port*."""

    return websockets.serve(handler, host, port)
