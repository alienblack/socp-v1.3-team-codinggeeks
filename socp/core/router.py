import hashlib
import os
from typing import Dict, Optional, Set, Tuple

SEEN_IDS: Set[str] = set()
LOCAL_SERVER_ID = "local"
LOCAL_USERS: Set[str] = set()
REMOTE_USERS: Dict[str, Set[str]] = {}
REMOTE_SERVER_ADDR: Dict[str, str] = {}
USER_LOCATION: Dict[str, str] = {}


def configure(local_server_id: str) -> None:
    global LOCAL_SERVER_ID
    LOCAL_SERVER_ID = local_server_id or "local"


def dedupe_key(ts: int, from_: str, to: str, payload: dict) -> str:
    h = hashlib.sha256(json_bytes(payload)).hexdigest()
    return f"{ts}|{from_}|{to}|{h}"


def json_bytes(d: dict) -> bytes:
    import json
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


def should_bypass_dedupe(payload: dict) -> bool:
    if os.getenv("VULN_REPLAY", "0") != "1":
        return False
    return payload.get("hops") == 0


def note_local_user(user_id: str) -> None:
    LOCAL_USERS.add(user_id)
    USER_LOCATION[user_id] = LOCAL_SERVER_ID


def drop_local_user(user_id: str) -> None:
    LOCAL_USERS.discard(user_id)
    if USER_LOCATION.get(user_id) == LOCAL_SERVER_ID:
        USER_LOCATION.pop(user_id, None)


def note_remote_user(server_id: str, user_id: str) -> None:
    if not server_id:
        return
    USER_LOCATION[user_id] = server_id
    REMOTE_USERS.setdefault(server_id, set()).add(user_id)


def note_remote_server(server_id: str, uri: Optional[str] = None) -> None:
    if not server_id or server_id == LOCAL_SERVER_ID:
        return
    if uri:
        REMOTE_SERVER_ADDR[server_id] = uri


def drop_remote_user(user_id: str, server_id: Optional[str] = None) -> None:
    server = server_id or USER_LOCATION.get(user_id)
    if server and server != LOCAL_SERVER_ID:
        members = REMOTE_USERS.get(server)
        if members is not None:
            members.discard(user_id)
            if not members:
                REMOTE_USERS.pop(server, None)
    if USER_LOCATION.get(user_id) == server:
        USER_LOCATION.pop(user_id, None)


def drop_remote_server(server_id: str) -> None:
    members = REMOTE_USERS.pop(server_id, set())
    for user in members:
        if USER_LOCATION.get(user) == server_id:
            USER_LOCATION.pop(user, None)
    REMOTE_SERVER_ADDR.pop(server_id, None)


def lookup_destination(user_id: str) -> Optional[str]:
    dest = USER_LOCATION.get(user_id)
    if dest == LOCAL_SERVER_ID:
        return "local"
    return dest


def list_all_users() -> dict:
    remote_detail = {
        srv: {
            "users": sorted(users),
            "uri": REMOTE_SERVER_ADDR.get(srv),
        }
        for srv, users in REMOTE_USERS.items()
    }
    return {
        "local": sorted(LOCAL_USERS),
        "remote": {srv: info["users"] for srv, info in remote_detail.items()},
        "remote_detail": remote_detail,
    }


def route_to_user(target_u: str, frame: dict, local_users: dict, user_locations: dict) -> Tuple[str, str]:
    if not should_bypass_dedupe(frame.get("payload", {})):
        dk = dedupe_key(frame["ts"], frame["from"], frame["to"], frame["payload"])
        if dk in SEEN_IDS:
            return ("error", "DUPLICATE")
        SEEN_IDS.add(dk)

    if target_u in local_users:
        return ("deliver_local", target_u)
    dest = user_locations.get(target_u)
    if dest and dest != "local":
        return ("forward", dest)

    fallback = lookup_destination(target_u)
    if fallback == "local":
        return ("deliver_local", target_u)
    if fallback:
        return ("forward", fallback)
    return ("error", "USER_NOT_FOUND")
