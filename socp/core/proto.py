"""Transport envelope helpers and signing utilities."""
from __future__ import annotations

import time
from typing import Any, Dict, Mapping, Optional

from pydantic import BaseModel, Field

from socp.utils.canonical import canonical_bytes

from . import crypto

__all__ = [
    "Envelope",
    "build_frame",
    "sign_transport",
    "verify_transport",
]


class Envelope(BaseModel):
    """Pydantic model describing the common transport envelope."""

    type: str
    from_: str = Field(alias="from")
    to: str
    ts: int
    payload: Dict[str, Any]
    sig: str = ""


ERROR_CODES = {"USER_NOT_FOUND", "INVALID_SIG", "BAD_KEY", "TIMEOUT", "UNKNOWN_TYPE", "NAME_IN_USE"}


def _require_mapping(data: Mapping[str, Any]) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        raise TypeError("payload must be a mapping")
    return data


def sign_transport(payload: Mapping[str, Any], server_priv_pem: bytes) -> str:
    """Produce a base64url-encoded transport signature for ``payload``."""

    canonical = canonical_bytes(dict(_require_mapping(payload)))
    signature = crypto.sign_pss_sha256(server_priv_pem, canonical)
    return crypto.b64url(signature)


def verify_transport(payload: Mapping[str, Any], sig_b64url: str, server_pub_pem: bytes) -> bool:
    """Verify a base64url transport signature against ``payload``."""

    try:
        signature = crypto.b64url_to_bytes(sig_b64url)
    except Exception:
        return False

    canonical = canonical_bytes(dict(_require_mapping(payload)))
    return crypto.verify_pss_sha256(server_pub_pem, canonical, signature)


def now_ms() -> int:
    """Return the current epoch timestamp in milliseconds."""

    return int(time.time() * 1000)


def build_frame(
    msg_type: str,
    from_id: str,
    to_id: str,
    payload: Optional[Dict[str, Any]] = None,
    *,
    ts: Optional[int] = None,
    sig: str = "",
) -> Dict[str, Any]:
    """Construct an envelope following the SOCP {type, from, to, ts, payload, sig} shape."""

    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dict")
    if ts is None:
        ts = now_ms()
    return {"type": msg_type, "from": from_id, "to": to_id, "ts": ts, "payload": payload, "sig": sig}
