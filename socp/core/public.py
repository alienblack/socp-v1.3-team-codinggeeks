"""Public channel membership and key distribution."""

from __future__ import annotations

import base64
import json
import logging
import secrets
import time
from typing import Any, Dict, Optional, Tuple

from . import crypto, store

log = logging.getLogger("socp.public")

_CHANNEL_ID = "public"
_CHANNEL_KEY: Optional[bytes] = None
_CHANNEL_VERSION: int = 0
_LOCAL_SERVER_ID: str = "unknown"
_GROUP_META: Dict[str, Any] = {}
_LOCAL_MEMBERS: Dict[str, Dict[str, Any]] = {}
_REMOTE_MEMBERS: Dict[str, Dict[str, Dict[str, Any]]] = {}


def configure(server_id: str) -> None:
    """Set the local server id so every payload lists the correct source."""
    global _LOCAL_SERVER_ID
    if server_id:
        _LOCAL_SERVER_ID = server_id
        for info in _LOCAL_MEMBERS.values():
            info["server_id"] = server_id


def _now_ms() -> int:
    """Return the current time in milliseconds for timestamps."""
    return int(time.time() * 1000)


def _db():
    """Reuse the shared database connection for public-channel tables."""
    return store._ensure_db()


async def ensure_public_group() -> None:
    """Ensure the public channel exists and load persistent state."""
    global _CHANNEL_KEY, _CHANNEL_VERSION, _GROUP_META

    await store.ensure_public_group()
    db = _db()
    cur = await db.execute("SELECT version, meta FROM groups WHERE group_id=?", (_CHANNEL_ID,))
    row = await cur.fetchone()
    await cur.close()

    version = 1
    meta_obj: Dict[str, Any] = {}
    if row:
        try:
            version = int(row["version"] or 1)
        except (KeyError, TypeError, ValueError):
            version = 1
        raw_meta = row["meta"]
        if raw_meta:
            try:
                meta_obj = json.loads(raw_meta)
            except (TypeError, json.JSONDecodeError):
                meta_obj = {}

    key_bytes: Optional[bytes] = None
    key_text = meta_obj.get("key") if isinstance(meta_obj, dict) else None
    if isinstance(key_text, str):
        try:
            key_bytes = base64.b64decode(key_text.encode("ascii"))
        except (ValueError, TypeError):
            key_bytes = None
    if key_bytes is None:
        key_bytes = secrets.token_bytes(32)
        meta_obj = dict(meta_obj or {})
        meta_obj["key"] = base64.b64encode(key_bytes).decode("ascii")
        await db.execute(
            "UPDATE groups SET meta=? WHERE group_id=?",
            (json.dumps(meta_obj), _CHANNEL_ID),
        )
        await db.commit()

    _CHANNEL_VERSION = int(version)
    _CHANNEL_KEY = key_bytes
    _GROUP_META = dict(meta_obj or {})

    _LOCAL_MEMBERS.clear()
    cur = await db.execute(
        "SELECT member_id, wrapped_key, added_at FROM group_members WHERE group_id=?",
        (_CHANNEL_ID,),
    )
    rows = await cur.fetchall()
    await cur.close()
    for row in rows or []:
        member_id = row["member_id"]
        wrapped = row["wrapped_key"]
        added_at = row["added_at"]
        if isinstance(member_id, str):
            _LOCAL_MEMBERS[member_id] = {
                "wrapped_key": wrapped,
                "added_at": added_at,
                "server_id": _LOCAL_SERVER_ID,
            }


def _channel_key() -> bytes:
    if _CHANNEL_KEY is None:
        raise RuntimeError("ensure_public_group() must be awaited before use")
    return _CHANNEL_KEY


async def _bump_version(db) -> None:
    """Increase the membership version whenever we change the roster."""
    global _CHANNEL_VERSION
    _CHANNEL_VERSION += 1
    await db.execute(
        "UPDATE groups SET version=?, meta=? WHERE group_id=?",
        (_CHANNEL_VERSION, json.dumps(_GROUP_META), _CHANNEL_ID),
    )
    await db.commit()


async def add_local_member(user_id: str, pubkey_pem: bytes) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Register a local user in the public channel.

    Returns a tuple ``(share_payload, gossip_payload)`` for delivery to the
    local user and for gossip to peer servers. ``None`` values indicate no
    change (e.g. user already enrolled).
    """

    if not user_id:
        return None, None
    if user_id in _LOCAL_MEMBERS:
        return None, None

    if _CHANNEL_KEY is None:
        await ensure_public_group()
    key = _channel_key()
    wrapped = crypto.rsa_encrypt_oaep(pubkey_pem, key)
    wrapped_b64 = base64.b64encode(wrapped).decode("ascii")
    now = _now_ms()

    db = _db()
    await db.execute(
        """
        INSERT OR REPLACE INTO group_members(group_id, member_id, role, wrapped_key, added_at)
        VALUES(?,?,?,?,?)
        """,
        (_CHANNEL_ID, user_id, "member", wrapped_b64, now),
    )
    _LOCAL_MEMBERS[user_id] = {
        "wrapped_key": wrapped_b64,
        "added_at": now,
        "server_id": _LOCAL_SERVER_ID,
    }
    await _bump_version(db)

    share_payload = {
        "channel": _CHANNEL_ID,
        "version": _CHANNEL_VERSION,
        "user": user_id,
        "wrapped_key": wrapped_b64,
    }
    gossip_payload = {
        "channel": _CHANNEL_ID,
        "version": _CHANNEL_VERSION,
        "user": user_id,
        "wrapped_key": wrapped_b64,
        "added_at": now,
        "server_id": _LOCAL_SERVER_ID,
    }
    return share_payload, gossip_payload


async def remove_local_member(user_id: str) -> Optional[Dict[str, Any]]:
    """Drop a local user from the public channel and announce the change."""
    if user_id not in _LOCAL_MEMBERS:
        return None
    db = _db()
    await db.execute(
        "DELETE FROM group_members WHERE group_id=? AND member_id=?",
        (_CHANNEL_ID, user_id),
    )
    _LOCAL_MEMBERS.pop(user_id, None)
    await _bump_version(db)
    return {
        "channel": _CHANNEL_ID,
        "version": _CHANNEL_VERSION,
        "user": user_id,
        "removed": True,
        "server_id": _LOCAL_SERVER_ID,
    }


def snapshot() -> Dict[str, Any]:
    """Return a serialisable picture of our known public channel members."""
    return {
        "channel": _CHANNEL_ID,
        "version": _CHANNEL_VERSION,
        "server_id": _LOCAL_SERVER_ID,
        "local": {user: dict(info) for user, info in _LOCAL_MEMBERS.items()},
        "remote": {
            server: {user: dict(meta) for user, meta in members.items()}
            for server, members in _REMOTE_MEMBERS.items()
        },
    }


def handle_remote_add(payload: Dict[str, Any]) -> None:
    """Track a remote server telling us it added a user to the channel."""
    if payload.get("channel") != _CHANNEL_ID:
        return
    server_id = payload.get("server_id")
    user = payload.get("user")
    if not isinstance(server_id, str) or not isinstance(user, str):
        return
    entry = {
        "wrapped_key": payload.get("wrapped_key"),
        "version": int(payload.get("version") or 0),
        "added_at": payload.get("added_at"),
        "server_id": server_id,
    }
    _REMOTE_MEMBERS.setdefault(server_id, {})[user] = entry


def handle_remote_update(payload: Dict[str, Any]) -> None:
    """Replace our view of another server's local members with a snapshot."""
    if payload.get("channel") != _CHANNEL_ID:
        return
    server_id = payload.get("server_id")
    if not isinstance(server_id, str):
        return
    members_payload = payload.get("local") if isinstance(payload.get("local"), dict) else {}
    members: Dict[str, Dict[str, Any]] = {}
    for user, info in members_payload.items():
        if isinstance(user, str):
            members[user] = dict(info) if isinstance(info, dict) else {}
            members[user]["server_id"] = server_id
    _REMOTE_MEMBERS[server_id] = members


def handle_remote_key_share(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Remember the wrapped key sent to us for one of our users."""
    if payload.get("channel") != _CHANNEL_ID:
        return None
    user = payload.get("user")
    wrapped = payload.get("wrapped_key")
    if not isinstance(user, str) or not isinstance(wrapped, str):
        return None
    _LOCAL_MEMBERS.setdefault(user, {})["wrapped_key"] = wrapped
    _LOCAL_MEMBERS[user]["server_id"] = _LOCAL_SERVER_ID
    return {
        "channel": _CHANNEL_ID,
        "version": int(payload.get("version") or _CHANNEL_VERSION),
        "wrapped_key": wrapped,
    }


def handle_remote_snapshot(server_id: str, users: Dict[str, Dict[str, Any]]) -> None:
    """Store a snapshot of who a remote server says is in the channel."""
    if not isinstance(server_id, str):
        return
    members: Dict[str, Dict[str, Any]] = {}
    for user in users.keys():
        if isinstance(user, str):
            members[user] = {"server_id": server_id}
    _REMOTE_MEMBERS[server_id] = members


def handle_remote_leave(server_id: str, user_id: str) -> None:
    """Forget a remote user when their host tells us they left."""
    if server_id in _REMOTE_MEMBERS:
        _REMOTE_MEMBERS[server_id].pop(user_id, None)
        if not _REMOTE_MEMBERS[server_id]:
            _REMOTE_MEMBERS.pop(server_id, None)


def handle_remote_disconnect(server_id: str) -> None:
    """Forget every user from a server that just disconnected."""
    _REMOTE_MEMBERS.pop(server_id, None)


__all__ = [
    "add_local_member",
    "configure",
    "ensure_public_group",
    "handle_remote_add",
    "handle_remote_disconnect",
    "handle_remote_key_share",
    "handle_remote_leave",
    "handle_remote_snapshot",
    "handle_remote_update",
    "remove_local_member",
    "snapshot",
]
