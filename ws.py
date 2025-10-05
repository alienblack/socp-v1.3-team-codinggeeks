from __future__ import annotations
import json
import time
import traceback
from typing import Tuple
from websockets.server import WebSocketServerProtocol
from .proto import Envelope
from .router import Router, Link

async def handle_connection(ws: WebSocketServerProtocol, path: str, router: Router):
link: Link | None = None
try:
#  First frame identity handshake
raw = await ws.recv() 
hello = json.loads(raw)
if not isinstance(hello, dict) or "type" not in hello:
await ws.close(code=1002, reason="Malformed HELLO")
return


htype = hello.get("type")
if htype == "USER_HELLO":
user_id = hello.get("user_id")
if not isinstance(user_id, str) or not user_id:
await ws.close(code=1002, reason="Bad USER_HELLO")
return
link = Link("user", user_id, ws)
router.register_user(user_id, link)
elif htype.startswith("SERVER_HELLO"):
server_id = hello.get("server_id")
if not isinstance(server_id, str) or not server_id:
await ws.close(code=1002, reason="Bad SERVER_HELLO")
return
link = Link("server", server_id, ws)
router.register_server(server_id, link)
# Optional: directory advertisement
for uid in hello.get("hosts", []):
if isinstance(uid, str):
router.learn_user_host(uid, server_id)
else:
await ws.close(code=1002, reason="Unknown HELLO")
return


# --- Main recv loop ---
while True:
data = await ws.recv() # text frames only
env = Envelope.from_json(data)
await router.route(env, origin=link)


except Exception:
# log and close politely
traceback.print_exc()
finally:
# unregister on disconnect
if link:
pass