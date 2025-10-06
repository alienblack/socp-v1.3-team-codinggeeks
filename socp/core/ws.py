import asyncio
import json
import logging
from typing import Any, Awaitable, Callable, Optional

import websockets

log = logging.getLogger("socp.ws")

MAX_FRAME_BYTES = 512 * 1024


class Link:
    def __init__(self, websocket):
        self.ws = websocket
        self.kind: Optional[str] = None

    async def send(self, frame: Any):
        if isinstance(frame, str):
            payload = frame
        else:
            payload = json.dumps(frame)
        await self.ws.send(payload)


async def serve(
    host: str,
    port: int,
    on_message_cb: Callable[[Link, str], Awaitable[None]],
    *,
    on_connect_cb: Optional[Callable[[Link], Awaitable[None]]] = None,
    on_disconnect_cb: Optional[Callable[[Link], Awaitable[None]]] = None,
    ssl: Any = None,
    max_size: int = MAX_FRAME_BYTES,
) -> None:
    async def handler(websocket):
        link = Link(websocket)
        if on_connect_cb:
            await on_connect_cb(link)
        try:
            async for message in websocket:
                await on_message_cb(link, message)
        except websockets.ConnectionClosed:
            pass
        finally:
            if on_disconnect_cb:
                await on_disconnect_cb(link)

    async with websockets.serve(handler, host, port, ssl=ssl, max_size=max_size):
        await asyncio.Future()
