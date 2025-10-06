from __future__ import annotations
import json
import time
import hashlib
from dataclasses import dataclass, asdict
from typing import Any, Dict, Tuple


REQUIRED_FIELDS = {"type", "from", "to", "ts", "payload", "sig"}

def _canon_json(obj: Any) -> str:
"""Deterministic JSON for hashing/signing."""
return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def payload_fingerprint(payload: Any) -> str:
"""SHA256 over canonical JSON payload (string hex)."""
h = hashlib.sha256(_canon_json(payload).encode("utf-8"))
return h.hexdigest()

@dataclass
class Envelope:
type: str
from_: str # "from" is a keyword in Python, store as from_
to: str
ts: int
payload: Any
sig: str

@staticmethod
def from_json(data: str) -> "Envelope":
try:
obj = json.loads(data)
except json.JSONDecodeError as e:
raise ValueError(f"invalid_json: {e}")


if not isinstance(obj, dict) or not REQUIRED_FIELDS.issubset(obj.keys()):
raise ValueError("missing_required_fields")


# Basic shape & types (be tolerant with payload)
t = obj["type"]
frm = obj["from"]
to = obj["to"]
ts = obj["ts"]
sig = obj["sig"]
if not isinstance(t, str) or not isinstance(frm, str) or not isinstance(to, str):
raise ValueError("bad_header_types")
if not isinstance(ts, int):
raise ValueError("ts_must_be_int_millis")
if not isinstance(sig, str):
raise ValueError("sig_must_be_str")


return Envelope(type=t, from_=frm, to=to, ts=ts, payload=obj.get("payload"), sig=sig)


def to_json(self) -> str:
d = {
"type": self.type,
"from": self.from_,
"to": self.to,
"ts": self.ts,
"payload": self.payload,
"sig": self.sig,
}
)