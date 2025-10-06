from __future__ import annotations
import asyncio
import os
import signal
import functools
from websockets.server import serve
from socp.core.router import Router
from socp.core.ws import handle_connection

async def main():
host = os.getenv("SOCP_HOST", "0.0.0.0")
port = int(os.getenv("SOCP_PORT", "8765"))
server_id = os.getenv("SOCP_SERVER_ID", f"srv-{os.uname().nodename}")


router = Router(server_id=server_id)


async with serve(lambda ws, p: handle_connection(ws, p, router), host, port):
print(f"[SOCP] Server {server_id} listening on ws://{host}:{port}")
stop = asyncio.Future()
for sig in (signal.SIGINT, signal.SIGTERM):
asyncio.get_running_loop().add_signal_handler(sig, stop.set_result, None)
await stop

if __name__ == "__main__":
asyncio.run(main())