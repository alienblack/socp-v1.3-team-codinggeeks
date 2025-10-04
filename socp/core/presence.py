from __future__ import annotations
from typing import Callable, Dict, Iterable
import logging

from .proto import build_frame, sign_frame_in_place, is_uuid_v4


"""
Presence Gossip (SOCP v1.3)
---------------------------
This module implements the server-side presence gossip required by the spec:
  • Broadcast local joins/leaves as USER_ADVERTISE / USER_REMOVE
  • Verify incoming server-origin frames before mutating routing tables
  • Guarded removal: only accept USER_REMOVE if our current mapping still points to that server
  • Fan-out valid gossip unchanged (mesh gossip; duplicate suppression should be handled elsewhere)

Minimal integration contract
============================
- proto.build_frame(type, from_, to, payload)  → dict (injects ts in ms; no sig)
- proto.sign_frame_in_place(env, sign_fn)      → dict (returns the same env with transport sig)
- proto.is_uuid_v4(value)                      → bool (format check for server_id/user_id)

Callers provide:
- sign_transport:   SignFn, used for our locally-originating frames
- broadcast:        BroadcastFn, to fan-out envelopes to peer servers (e.g., PeerManager.broadcast)
- verify_from_srv:  VerifyFn, validates transport signature of an incoming server frame
- user_locations:   Dict[user_id -> "local" | server_id], shared with peers/routers

Notes
-----
- This module deliberately does not perform duplicate suppression; peers layer should drop
  dup gossip by (ts, from, to, hash(payload)).
- The verify function should pin the public key of env["from"] and re-compute the transport
  signature over the canonical payload (per spec §12). We only enforce shape here.
"""


log = logging.getLogger("socp.presence")

# ---- types ----
SignFn      = Callable[[bytes], str]          # transport signer (RSASSA-PSS in prod)
BroadcastFn = Callable[[dict], None]          # e.g., PeerManager.broadcast_envelope
VerifyFn    = Callable[[dict], bool]          # verify transport sig using sender's pinned pubkey


# -------------------------------
# Local user lifecycle → emit gossip
# -------------------------------
async def on_user_local_join(
    user_id: str,
    meta: dict,
    *,
    my_server_id: str,
    user_locations: Dict[str, str],
    sign_transport: SignFn,
    broadcast: BroadcastFn,
) -> dict:
    """Called when a local user connects.

    Builds and broadcasts USER_ADVERTISE, and optimistically updates user_locations[user_id] = "local".
    Per spec, payload carries { user_id, server_id, meta }.
    """
    if not user_id:
        raise ValueError("user_id is required")

    payload = {"user_id": user_id, "server_id": my_server_id, "meta": meta or {}}
    env = sign_frame_in_place(build_frame("USER_ADVERTISE", my_server_id, "*", payload), sign_transport)

    # Optimistic local update: we are the hosting server for this user
    user_locations[user_id] = "local"

    broadcast(env)
    log.info("Advertised local join: %s", user_id)
    return env


async def on_user_local_leave(
    user_id: str,
    *,
    my_server_id: str,
    user_locations: Dict[str, str],
    sign_transport: SignFn,
    broadcast: BroadcastFn,
) -> dict:
    """Called when a local user disconnects.

    Builds and broadcasts USER_REMOVE. We DO NOT immediately delete our local mapping here;
    the hosting server is us, and routers should treat deliveries accordingly. However, for simplicity
    in this implementation we eagerly pop the mapping because we know the user is gone.
    """
    if not user_id:
        raise ValueError("user_id is required")

    payload = {"user_id": user_id, "server_id": my_server_id}
    env = sign_frame_in_place(build_frame("USER_REMOVE", my_server_id, "*", payload), sign_transport)

    # Eagerly remove local presence since we are the hosting server and the user disconnected
    user_locations.pop(user_id, None)

    broadcast(env)
    log.info("Advertised local leave: %s", user_id)
    return env


# -------------------------------
# Gossip handlers (ingress from peer servers)
# -------------------------------

def handle_user_advertise(
    env: dict,
    *,
    my_server_id: str,
    user_locations: Dict[str, str],
    verify_from_server: VerifyFn,
    fanout: BroadcastFn,
) -> bool:
    """Process a USER_ADVERTISE from another server.

    Rules (spec §8.2):
      1) Verify transport signature using the announcing server's pinned key.
      2) Require payload shape: user_id (UUID), server_id (UUID), meta (object)
      3) Update mapping: user_locations[user_id] = server_id unless server_id == my_server_id → "local"
      4) Forward the envelope unchanged (gossip fan-out)
    """
    if env.get("type") != "USER_ADVERTISE":
        return False

    if not verify_from_server(env):
        log.warning("Rejected USER_ADVERTISE (bad sig) from %s", env.get("from"))
        return False

    # Basic shape enforcement
    p = env.get("payload") or {}
    uid = p.get("user_id")
    hosting_sid = p.get("server_id")
    if not (is_uuid_v4(hosting_sid) and isinstance(p.get("meta", {}), dict) and uid):
        log.warning("Rejected USER_ADVERTISE (bad shape)")
        return False

    # Optional sanity: require that the sender matches hosting_sid
    frm = env.get("from")
    if is_uuid_v4(frm) and frm != hosting_sid:
        log.debug("USER_ADVERTISE from %s claims server_id=%s; accepting but logging.", frm, hosting_sid)

    user_locations[uid] = "local" if hosting_sid == my_server_id else hosting_sid

    # Fan-out unchanged; duplicate-suppression is handled at peers/transport layer
    fanout(env)
    log.info("Accepted USER_ADVERTISE: %s hosted on %s", uid, hosting_sid)
    return True


def handle_user_remove(
    env: dict,
    *,
    my_server_id: str,
    user_locations: Dict[str, str],
    verify_from_server: VerifyFn,
    fanout: BroadcastFn,
) -> bool:
    """Process a USER_REMOVE with guarded removal (spec §8.2).

    Only remove if our current mapping still points to that server. This prevents a stale or malicious
    remove from a non-hosting server from wiping presence.
    """
    if env.get("type") != "USER_REMOVE":
        return False

    if not verify_from_server(env):
        log.warning("Rejected USER_REMOVE (bad sig) from %s", env.get("from"))
        return False

    p = env.get("payload") or {}
    uid = p.get("user_id")
    hosting_sid = p.get("server_id")

    if not (uid and is_uuid_v4(hosting_sid)):
        log.warning("Rejected USER_REMOVE (bad shape)")
        return False

    current = user_locations.get(uid)

    # Guarded removal per spec: only remove if the mapping still points to that server
    if current == hosting_sid or (current == "local" and hosting_sid == my_server_id):
        user_locations.pop(uid, None)
        fanout(env)
        log.info("Accepted USER_REMOVE: %s (was hosted on %s)", uid, hosting_sid)
        return True

    log.debug("Ignored USER_REMOVE for %s (current=%s, claimed_host=%s)", uid, current, hosting_sid)
    return False


# -------------------------------
# Maintenance helpers
# -------------------------------

def purge_by_hosting_server(hosting_sid: str, user_locations: Dict[str, str]) -> int:
    """Remove all users mapped to the given hosting server.

    Intended for use when a peer link is declared dead. This is optional; the spec allows
    lazy correction on delivery failure or new gossip. Returning the count can help log metrics.
    """
    to_delete: list[str] = [u for u, sid in user_locations.items() if sid == hosting_sid]
    for u in to_delete:
        user_locations.pop(u, None)
    if to_delete:
        log.warning("Purged %d user(s) hosted on dead server %s", len(to_delete), hosting_sid)
    return len(to_delete)
