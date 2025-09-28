
import logging
from typing import Callable, Dict
from .proto import build_frame, sign_frame_in_place

log = logging.getLogger("socp.presence")


user_locations: Dict[str, str] = {}

# type aliases
SignFn = Callable[[bytes], str]          # transport signer (RSA-PSS in prod; HMAC stub in tests)
BroadcastFn = Callable[[dict], None]     # e.g., PeerManager.broadcast_envelope
VerifyFn = Callable[[dict], bool]        # given an envelope, verify sig with sender's pinned pubkey

async def on_user_local_join(
    user_id: str, 
    meta: dict,
    *,
    my_server_id: str,
    sign_transport: SignFn,
    broadcast: BroadcastFn,)->dict:
    
    """
    Called when a local user connects.
    Builds and broadcasts a USER_ADVERTISE envelope.
    """
    payload = {"user_id": user_id, "server_id": my_server_id, "meta": meta or {}}
    
    frame = build_frame("USER_ADVERTISE", my_server_id, "*", payload)
    env = sign_frame_in_place(frame, sign_transport)

    # optimistic update for our own table
    user_locations[user_id] = "local"

    broadcast(env)
    log.info("Advertise user join: %s", user_id)
    return env

async def on_user_local_leave(user_id: str, *,
    my_server_id: str,
    sign_transport: SignFn,
    broadcast: BroadcastFn)->dict:
    
    """
    Called when a local user disconnects.
    Builds and broadcasts a USER_REMOVE envelope.
    """

    payload = {"user_id": user_id, "server_id": my_server_id}
    
    frame = build_frame("USER_REMOVE", my_server_id, "*", payload)
    env = sign_frame_in_place(frame, sign_transport)    

    broadcast(env)
    log.info("Advertise user leave: %s", user_id)
    return env

# -------------------------------
# gossip handlers
# -------------------------------

def handle_user_advertise(
    env: dict,
    *,
    my_server_id: str,
    verify_from_server: VerifyFn,
    fanout: BroadcastFn,
) -> bool:
    """
    Process a USER_ADVERTISE from another server.
    Updates user_locations and fans out unchanged envelope.
    """
    if env.get("type") != "USER_ADVERTISE":
        return False
    if not verify_from_server(env):
        log.warning("Rejected USER_ADVERTISE (bad sig) from %s", env.get("from"))
        return False

    payload = env["payload"]
    uid, hosting_sid = payload["user_id"], payload["server_id"]
    user_locations[uid] = "local" if hosting_sid == my_server_id else hosting_sid
    fanout(env)
    log.info("Processed USER_ADVERTISE for %s hosted on %s", uid, hosting_sid)
    return True


def handle_user_remove(
    env: dict,
    *,
    my_server_id: str,
    verify_from_server: VerifyFn,
    fanout: BroadcastFn,
) -> bool:
    """
    Process a USER_REMOVE with guarded removal.
    Only accept if the hosting server matches current mapping.
    """
    if env.get("type") != "USER_REMOVE":
        return False
    if not verify_from_server(env):
        log.warning("Rejected USER_REMOVE (bad sig) from %s", env.get("from"))
        return False

    payload = env["payload"]
    uid, hosting_sid = payload["user_id"], payload["server_id"]

    current = user_locations.get(uid)
    if current in ("local", hosting_sid):
        user_locations.pop(uid, None)
        fanout(env)
        log.info("Processed USER_REMOVE for %s hosted on %s", uid, hosting_sid)
        return True

    log.debug("Ignored USER_REMOVE for %s (not hosted on %s)", uid, hosting_sid)
    return False

