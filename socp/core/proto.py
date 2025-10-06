
from __future__ import annotations

from time import time
from typing import Any, Dict, Mapping, Optional

import json
from pydantic import BaseModel, Field, ValidationError, field_validator


class FrameValidationError(ValueError):
    """Raised when a websocket frame cannot be coerced into an :class:`Envelope`."""


class Envelope(BaseModel):
    """Typed representation of a SOCP transport envelope."""

    type: str = Field(min_length=1)
    from_: str = Field(alias="from", min_length=1)
    to: str = Field(min_length=1)
    ts: int
    payload: Dict[str, Any]
    sig: str = ""

    model_config = {"populate_by_name": True, "extra": "forbid"}

    @field_validator("ts")
    @classmethod
    def _ts_is_positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("timestamp must be positive millisecond epoch")
        return value


ERROR_CODES = {
    "USER_NOT_FOUND",
    "INVALID_SIG",
    "BAD_KEY",
    "TIMEOUT",
    "UNKNOWN_TYPE",
    "NAME_IN_USE",
    "DUPLICATE",
}


def parse_envelope(raw_frame: str | Mapping[str, Any]) -> Envelope:
    """Parse and validate a raw websocket frame into an :class:`Envelope`.

    ``raw_frame`` may either be a JSON string or an already decoded mapping.
    A :class:`FrameValidationError` is raised when validation fails.
    """

    if isinstance(raw_frame, str):
        try:
            decoded: Any = json.loads(raw_frame)
        except json.JSONDecodeError as exc:  # pragma: no cover - json lib tested elsewhere
            raise FrameValidationError("frame is not valid JSON") from exc
    else:
        decoded = raw_frame

    if not isinstance(decoded, Mapping):
        raise FrameValidationError("frame payload must be a JSON object")

    try:
        return Envelope.model_validate(decoded)
    except ValidationError as exc:  # pragma: no cover - exercised in tests
        raise FrameValidationError(str(exc)) from exc


def build_frame(type: str, from_: str, to: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Build a JSON-serialisable envelope ready for transport."""

    return {
        "type": type,
        "from": from_,
        "to": to,
        "ts": int(time() * 1000),
        "payload": dict(payload),
        "sig": "",
    }


def make_ack(from_: str, to: str, ref_type: str, ref_ts: int, extra: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Create a transport-level acknowledgement frame."""

    payload: Dict[str, Any] = {"ref": ref_type, "ts": ref_ts}
    if extra:
        payload.update(extra)
    return build_frame("ACK", from_, to, payload)


def make_error(from_: str, to: str, code: str, message: Optional[str] = None) -> Dict[str, Any]:
    """Create a transport-level error frame with a canonical payload."""

    if code not in ERROR_CODES:
        raise ValueError(f"Unknown error code '{code}'")
    payload: Dict[str, Any] = {"code": code}
    if message:
        payload["message"] = message
    return build_frame("ERROR", from_, to, payload)
