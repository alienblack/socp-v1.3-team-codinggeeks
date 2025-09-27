
import asyncio, websockets, logging, json
log = logging.getLogger("socp.ws")

class Link:
    def __init__(self, websocket):
        self.ws = websocket

    async def send(self, frame: dict):
        await self.ws.send(json.dumps(frame))

async def serve(host, port, on_message_cb):
    async def handler(websocket):
        link = Link(websocket)
        async for message in websocket:
            await on_message_cb(link, message)
    async with websockets.serve(handler, host, port):
        await asyncio.Future()  # run forever
