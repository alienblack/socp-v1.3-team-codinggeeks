from __future__ import annotations

import time
from typing import Any, Dict

from pydantic import BaseModel, Field, validator

from socp.utils.canonical import canonical_bytes
from socp.core import crypto

ERROR_CODES = {
    "USER_NOT_FOUND",
    "INVALID_SIG",
    "BAD_KEY",
    "TIMEOUT",
    "UNKNOWN_TYPE",
    "NAME_IN_USE",
}


class Envelope(BaseModel):
    """SOCP transport envelope as per SOCP v1.3."""

    type: str
    from_: str = Field(alias="from")
    to: str
    ts: int
    payload: Dict[str, Any]
    sig: str = ""

    class Config:
        allow_population_by_field_name = True
        populate_by_name = True

    @validator("ts")
    def _validate_ts(cls, value: int) -> int:  # noqa: D401
        """Ensure timestamps are non-negative."""
        if value < 0:
            raise ValueError("timestamp must be non-negative")
        return value


def now_ms() -> int:
    """Return current time in milliseconds since epoch."""

    return int(time.time() * 1000)


def build_envelope(type: str, from_: str, to: str, payload: Dict[str, Any], *, ts: int | None = None) -> Envelope:
    """Construct an unsigned envelope."""

    if ts is None:
        ts = now_ms()
    return Envelope(type=type, from_=from_, to=to, ts=ts, payload=payload, sig="")


def sign_envelope(envelope: Envelope, privkey_pem: bytes) -> Envelope:
    """Attach a transport signature to the envelope."""

    signature = crypto.b64url(crypto.sign_pss_sha256(privkey_pem, canonical_bytes(envelope.payload)))
    envelope.sig = signature
    return envelope


def verify_envelope(envelope: Envelope, pubkey_pem: bytes) -> bool:
    """Verify the transport signature using the provided public key."""

    if not envelope.sig:
        return False
    try:
        signature = crypto.b64url_decode(envelope.sig)
    except ValueError:
        return False
    return crypto.verify_pss_sha256(pubkey_pem, canonical_bytes(envelope.payload), signature)


def envelope_to_dict(envelope: Envelope) -> Dict[str, Any]:
    """Return the transport envelope as a JSON-serialisable dict."""

    return envelope.model_dump(by_alias=True)
