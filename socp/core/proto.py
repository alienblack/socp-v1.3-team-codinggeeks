
from pydantic import BaseModel, Field
from typing import Any, Literal, Dict

class Envelope(BaseModel):
    type: str
    from_: str = Field(alias="from")
    to: str
    ts: int
    payload: Dict[str, Any]
    sig: str = ""

ERROR_CODES = {"USER_NOT_FOUND","INVALID_SIG","BAD_KEY","TIMEOUT","UNKNOWN_TYPE","NAME_IN_USE"}

def build_frame(type: str, from_: str, to: str, payload: dict) -> dict:
    from time import time
    return {"type": type, "from": from_, "to": to, "ts": int(time()*1000), "payload": payload, "sig": ""}

# --- Helpers added for crypto transport signing & envelope building ---
from . import crypto
from socp.utils.canonical import canonical_bytes
import base64, time
from typing import Dict, Any, Optional

def sign_transport(payload: dict, server_priv_pem: bytes) -> str:
    sig = crypto.sign_pss_sha256(server_priv_pem, canonical_bytes(payload))
    return crypto.b64url(sig)

def verify_transport(payload: dict, sig_b64url: str, server_pub_pem: bytes) -> bool:
    try:
        sig = crypto.b64url_to_bytes(sig_b64url)
    except Exception:
        return False
    return crypto.verify_pss_sha256(server_pub_pem, canonical_bytes(payload), sig)

def now_ms() -> int:
    return int(time.time() * 1000)

def build_frame(msg_type: str, from_id: str, to_id: str, payload: Optional[Dict[str, Any]] = None, *, ts: Optional[int] = None, sig: str = "") -> Dict[str, Any]:
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dict")
    if ts is None:
        ts = now_ms()
    return {"type": msg_type, "from": from_id, "to": to_id, "ts": ts, "payload": payload, "sig": sig}
