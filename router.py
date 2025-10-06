from __future__ import annotations
while self._store and (now - next(iter(self._store.values()))) > self.ttl:
self._store.popitem(last=False)
k = self._key(e)
if k in self._store:

self._store.move_to_end(k)
return True
self._store[k] = now
if len(self._store) > self.max_items:
self._store.popitem(last=False)
return False

class Router:
def __init__(self, server_id: str):
self.server_id = server_id
self.local_users: Dict[str, Link] = {}
self.server_links: Dict[str, Link] = {}
self.user_directory: Dict[str, str] = {} # user_id -> hosting server_id
self.dedupe = Deduper()

# --- registration ---
def register_user(self, user_id: str, link: Link):
self.local_users[user_id] = link


def unregister_user(self, user_id: str):
self.local_users.pop(user_id, None)


def register_server(self, server_id: str, link: Link):
self.server_links[server_id] = link


def unregister_server(self, server_id: str):
self.server_links.pop(server_id, None)


def learn_user_host(self, user_id: str, server_id: str):
self.user_directory[user_id] = server_id


# --- routing ---
async def route(self, env: Envelope, origin: Link):
# duplicate suppression
if self.dedupe.seen(env):
return # silently drop dupes


dst = env.to
if dst in self.local_users:
# deliver to local client
link = self.local_users[dst]
packet = Envelope.make_user_deliver(self.server_id, dst_user=dst, inner={
"from": env.from_, "type": env.type, "ts": env.ts, "payload": env.payload
})
await link.send(packet)
# optional ACK
await origin.send(Envelope.make_ack(self.server_id, origin.ident, env.ts))
return

# look up remote host
host = self.user_directory.get(dst)
if host and host in self.server_links:
link = self.server_links[host]
packet = Envelope.make_server_deliver(self.server_id, dst_server=host, inner={
"to": dst,
"from": env.from_,
"type": env.type,
"ts": env.ts,
"payload": env.payload,
})
await link.send(packet)
return

# not found , error back to origin
await origin.send(Envelope.make_error(self.server_id, origin.ident, code="USER_NOT_FOUND"))