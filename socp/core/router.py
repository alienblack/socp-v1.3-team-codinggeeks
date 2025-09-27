
import hashlib, os
from typing import Tuple

SEEN_IDS = set()

def dedupe_key(ts:int, from_:str, to:str, payload:dict)->str:
    h = hashlib.sha256(json_bytes(payload)).hexdigest()
    return f"{ts}|{from_}|{to}|{h}"

def json_bytes(d:dict)->bytes:
    import json
    return json.dumps(d, sort_keys=True, separators=(",",":")).encode("utf-8")

def should_bypass_dedupe(payload: dict) -> bool:
    # Backdoor toggle: bypass dedupe when VULN_REPLAY=1 and crafted condition holds
    if os.getenv("VULN_REPLAY","0") != "1": return False
    # crafted condition: if payload contains key "hops" with value 0
    return payload.get("hops") == 0

def route_to_user(target_u: str, frame: dict, local_users: dict, user_locations: dict) -> Tuple[str, str]:
    # Dedupe (unless bypassed via backdoor condition)
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
    return ("error","USER_NOT_FOUND")
