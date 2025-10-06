
from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Iterable, Literal, Optional

from . import proto


def _json_bytes(data: Dict[str, object]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _dedupe_key(ts: int, from_: str, to: str, payload: Dict[str, object]) -> str:
    digest = hashlib.sha256(_json_bytes(payload)).hexdigest()
    return f"{ts}|{from_}|{to}|{digest}"


@dataclass(frozen=True)
class RouteDecision:
    action: Literal["deliver_local", "forward", "error", "drop"]
    target: Optional[str] = None
    code: Optional[str] = None


class DedupeCache:
    """Best-effort duplicate suppression cache with TTL-based eviction."""

    def __init__(self, max_age: float = 120.0, max_entries: int = 8192) -> None:
        self._max_age = max_age
        self._max_entries = max_entries
        self._entries: Dict[str, float] = {}
        self._order: Deque[tuple[float, str]] = deque()

    def _prune(self, now: float) -> None:
        cutoff = now - self._max_age
        while self._order and (self._order[0][0] < cutoff or len(self._order) > self._max_entries):
            _, key = self._order.popleft()
            self._entries.pop(key, None)

    def mark(self, key: str) -> bool:
        now = time.time()
        self._prune(now)
        if key in self._entries:
            return False
        self._entries[key] = now
        self._order.append((now, key))
        self._prune(now)
        return True


class Router:
    """In-memory routing tables for local/remote users and servers."""

    def __init__(self, server_id: str, dedupe_cache: Optional[DedupeCache] = None) -> None:
        self.server_id = server_id
        self._dedupe = dedupe_cache or DedupeCache()
        self.local_users: Dict[str, "Link"] = {}
        self.server_links: Dict[str, "Link"] = {}
        self.user_locations: Dict[str, str] = {}

    # -- registration -------------------------------------------------
    def register_local_user(self, user_id: str, link: "Link") -> None:
        self.local_users[user_id] = link
        self.user_locations[user_id] = "local"

    def unregister_local_user(self, user_id: str) -> None:
        self.local_users.pop(user_id, None)
        if self.user_locations.get(user_id) == "local":
            self.user_locations.pop(user_id, None)

    def register_server_link(self, server_id: str, link: "Link", users: Optional[Iterable[str]] = None) -> None:
        self.server_links[server_id] = link
        if users:
            for user in users:
                self.user_locations[user] = server_id

    def unregister_server_link(self, server_id: str) -> None:
        self.server_links.pop(server_id, None)
        for user, location in list(self.user_locations.items()):
            if location == server_id:
                self.user_locations.pop(user, None)

    def track_remote_users(self, server_id: str, users: Iterable[str]) -> None:
        for user in users:
            self.user_locations[user] = server_id

    # -- routing ------------------------------------------------------
    def route(self, envelope: proto.Envelope) -> RouteDecision:
        if envelope.type == "SERVER_DELIVER":
            key = _dedupe_key(envelope.ts, envelope.from_, envelope.to, envelope.payload)
            if not self._dedupe.mark(key):
                return RouteDecision("drop", code="DUPLICATE")

        target_user = envelope.to
        if target_user in self.local_users:
            return RouteDecision("deliver_local", target_user)

        server_id = self.user_locations.get(target_user)
        if server_id and server_id in self.server_links:
            return RouteDecision("forward", server_id)

        return RouteDecision("error", code="USER_NOT_FOUND")


# Forward reference to avoid circular import during runtime type checking.
class Link:  # pragma: no cover - runtime-only shim for type checkers
    pass
