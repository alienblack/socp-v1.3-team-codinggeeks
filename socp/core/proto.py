
from pydantic import BaseModel, Field
from typing import Any, Dict, Tuple
import time, uuid, base64, json
from typing import Callable, Union

class Envelope(BaseModel):
    type: str
    from_: str = Field(alias="from")
    to: str
    ts: int
    payload: Dict[str, Any]
    sig: str = ""

class ProtocolError(Exception):
    """Exception carrying one of ERROR_CODES for validation/verification failures."""
    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        
ERROR_CODES = {"USER_NOT_FOUND","INVALID_SIG","BAD_KEY","TIMEOUT","UNKNOWN_TYPE","NAME_IN_USE"}

def now_ms() -> int:
    return int(time()*1000)

def build_frame(type: str, from_: str, to: str, payload: dict) -> dict:
    return {"type": type, 
            "from": from_, 
            "to": to, 
            "ts": int(time()*1000), 
            "payload": payload,
            "sig": ""}

# Spec: all Server/User IDs are UUID v4 (except that during bootstrap, `to` may be "IP:port")
def is_uuid_v4(s: str) -> bool:
    try:
        u = uuid.UUID(str(s))
        return u.version == 4
    except Exception:
        return False

# Spec: all binary blobs in JSON are base64url (unpadded)
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

# Canonicalise payload for transport signature: sorted keys, no spaces
def canonical_payload_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

# Transport signing interface (wire to real RSA-4096 PSS(SHA-256) in your crypto layer)
SignFn  = Callable[[bytes], str]           # returns base64url(signature)
VerifyFn = Callable[[bytes, str], bool]    # (data, base64url(sig)) -> bool

# very light IP:port check for introducer/bootstrap special case (leave real validation to networking layer)
def _is_ip_port(s: str) -> bool:
    if ":" not in s:
        return False
    host, port = s.rsplit(":", 1)
    if not host or not port.isdigit():
        return False
    return True

def validate_envelope(
    env: Union[Dict[str, Any], Envelope],
    *,
    allow_ip_port_to: bool = False,
    expect_sig: bool = False,
) -> None:
    """
    Raise ProtocolError with an ERROR_CODES code if invalid.
    Does NOT verify the cryptographic signature; see verify_envelope().
    """
    e = env.model_dump(by_alias=True) if isinstance(env, Envelope) else dict(env)

    # minimal shape/type checks
    for k in ("type", "from", "to", "ts", "payload", "sig"):
        if k not in e:
            raise ProtocolError("UNKNOWN_TYPE", f"Missing required field: {k}")
    if not isinstance(e["type"], str) or not e["type"]:
        raise ProtocolError("UNKNOWN_TYPE", "Invalid or empty 'type'")
    if not isinstance(e["ts"], int):
        raise ProtocolError("BAD_KEY", "'ts' must be an integer (ms)")
    if not isinstance(e["payload"], dict):
        raise ProtocolError("BAD_KEY", "'payload' must be an object")

    # identifier rules: from = UUIDv4; to = UUIDv4 or "*" (or IP:port when explicitly allowed)
    if not is_uuid_v4(e["from"]):
        raise ProtocolError("BAD_KEY", "Invalid 'from' (must be UUID v4)")
    to_ok = e["to"] == "*" or is_uuid_v4(e["to"]) or (allow_ip_port_to and _is_ip_port(e["to"]))
    if not to_ok:
        raise ProtocolError("BAD_KEY", "Invalid 'to' (must be UUID v4, '*', or IP:port when allowed)")

    # signature presence policy (cryptographic correctness is checked separately)
    if expect_sig and not e.get("sig"):
        raise ProtocolError("INVALID_SIG", "Signature required but missing")

def sign_frame_in_place(frame: Dict[str, Any], sign_transport: SignFn) -> Dict[str, Any]:
    """
    Computes and sets the transport signature over the canonicalised payload.
    Mutates and returns the same dict produced by build_frame(...).
    """
    if not isinstance(frame, dict) or "payload" not in frame:
        raise ProtocolError("BAD_KEY", "Frame shape is invalid for signing")
    frame["sig"] = sign_transport(canonical_payload_bytes(frame["payload"]))
    return frame

def verify_envelope(
    env: Union[Dict[str, Any], Envelope],
    verify_transport: VerifyFn,
    *,
    allow_ip_port_to: bool = False,
    expect_sig: bool = True
) -> Tuple[bool, Union[str, None]]:
    """
    Validate structure & IDs and verify signature.
    Returns (ok, error_code_or_None). On failure, error_code is from ERROR_CODES.
    """
    try:
        # structural + policy checks first
        validate_envelope(env, allow_ip_port_to=allow_ip_port_to, expect_sig=expect_sig)

        e = env.model_dump(by_alias=True) if isinstance(env, Envelope) else env
        sig = e.get("sig", "")
        if sig:
            ok = verify_transport(canonical_payload_bytes(e["payload"]), sig)
            if not ok:
                return (False, "INVALID_SIG")
        # If sig not present and not expected, it’s fine; validate_envelope already enforced presence when needed.
        return (True, None)
    except ProtocolError as pe:
        # Map to known ERROR_CODES (already enforced), fall back to BAD_KEY if unknown
        code = pe.code if pe.code in ERROR_CODES else "BAD_KEY"
        return (False, code)

