import json
from dataclasses import dataclass
from typing import Any, Dict, Mapping, MutableMapping

ERROR_CODES = {"USER_NOT_FOUND", "INVALID_SIG", "BAD_KEY", "TIMEOUT", "UNKNOWN_TYPE", "NAME_IN_USE"}


@dataclass
class Envelope:
    type: str
    from_: str
    to: Any
    ts: int
    payload: Dict[str, Any]
    sig: str = ""

    def __init__(self, **data: Any) -> None:
        raw = dict(data)
        if "type" not in raw:
            raise ValueError("missing type")
        self.type = str(raw["type"])

        if "from" in raw and "from_" not in raw:
            raw["from_"] = raw.pop("from")
        if "from_" not in raw:
            raise ValueError("missing from")
        self.from_ = str(raw["from_"])

        self.to = raw.get("to")

        ts = raw.get("ts")
        if not isinstance(ts, int):
            raise ValueError("ts must be int")
        self.ts = ts

        payload = raw.get("payload")
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            payload = dict(payload)
        self.payload = payload

        sig = raw.get("sig", "")
        if not isinstance(sig, str):
            raise ValueError("sig must be str")
        self.sig = sig

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "from": self.from_,
            "to": self.to,
            "ts": self.ts,
            "payload": self.payload,
            "sig": self.sig,
        }

    def copy(self) -> "Envelope":
        return Envelope(**self.to_dict())


def build_frame(type: str, from_: str, to: Any, payload: Mapping[str, Any]) -> Dict[str, Any]:
    from time import time

    return {
        "type": type,
        "from": from_,
        "to": to,
        "ts": int(time()),
        "payload": dict(payload),
        "sig": "",
    }


def canonical_body(env: Envelope | Mapping[str, Any]) -> Dict[str, Any]:
    if isinstance(env, Envelope):
        return {
            "type": env.type,
            "from": env.from_,
            "to": env.to,
            "ts": env.ts,
            "payload": env.payload,
        }

    data: Mapping[str, Any] = env
    payload = data.get("payload")
    return {
        "type": data.get("type"),
        "from": data.get("from") or data.get("from_"),
        "to": data.get("to"),
        "ts": data.get("ts"),
        "payload": payload,
    }


def canonical_bytes(env: Envelope | Mapping[str, Any]) -> bytes:
    body = canonical_body(env)
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def attach_signature(frame: MutableMapping[str, Any], signature: str) -> MutableMapping[str, Any]:
    frame["sig"] = signature
    return frame


__all__ = ["Envelope", "ERROR_CODES", "build_frame", "canonical_body", "canonical_bytes", "attach_signature"]
