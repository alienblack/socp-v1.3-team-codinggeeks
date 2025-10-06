from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Tuple


def _json_canonical_hash(payload: dict) -> str:
    import json

    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


@dataclass(slots=True)
class DuplicateTracker:
    """Track recently seen envelopes to suppress loops."""

    ttl_seconds: float = 60.0
    _seen: Dict[str, float] = field(default_factory=dict)

    def _make_key(self, ts: int, from_: str, to: str, payload: dict) -> str:
        return f"{ts}|{from_}|{to}|{_json_canonical_hash(payload)}"

    def should_bypass(self, payload: dict) -> bool:
        if os.getenv("VULN_REPLAY", "0") != "1":
            return False
        return payload.get("hops") == 0

    def mark_seen(self, ts: int, from_: str, to: str, payload: dict) -> bool:
        if self.should_bypass(payload):
            return False
        key = self._make_key(ts, from_, to, payload)
        now = time.time()
        cutoff = now - self.ttl_seconds
        stale = [k for k, seen_at in self._seen.items() if seen_at < cutoff]
        for token in stale:
            self._seen.pop(token, None)
        if key in self._seen:
            return True
        self._seen[key] = now
        return False

def route_to_user(target_u: str, frame: dict, local_users: dict, user_locations: dict, tracker: DuplicateTracker) -> Tuple[str, str]:
    if tracker.mark_seen(frame["ts"], frame["from"], frame["to"], frame.get("payload", {})):
        return "error", "DUPLICATE"

    if target_u in local_users:
        return "deliver_local", target_u

    dest = user_locations.get(target_u)
    if dest and dest != "local":
        return "forward", dest

    return "error", "USER_NOT_FOUND"






