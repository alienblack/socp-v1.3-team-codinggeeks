import logging
from typing import Any, Awaitable, Callable, Dict, Optional

from . import public, router

log = logging.getLogger("socp.presence")

_BROADCAST: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None
_SERVER_ID = "unknown"
_LOCAL_META: Dict[str, Dict[str, Any]] = {}
_REMOTE_META: Dict[str, Dict[str, Dict[str, Any]]] = {}


def configure(
    server_id: str,
    broadcaster: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]],
) -> None:
    """Save helpers so the presence layer knows who we are and how to gossip."""
    global _SERVER_ID, _BROADCAST
    _SERVER_ID = server_id or "unknown"
    _BROADCAST = broadcaster


def snapshot_local_users() -> Dict[str, Dict[str, Any]]:
    """Return a copy of every user currently connected to this server."""
    return {user: meta.copy() for user, meta in _LOCAL_META.items()}


def snapshot_remote_users() -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Return a copy of remote users grouped by their hosting server."""
    return {srv: {user: meta.copy() for user, meta in users.items()} for srv, users in _REMOTE_META.items()}


def list_online() -> Dict[str, Any]:
    """Summarise the users we know about for status responses."""
    return {
        "server": _SERVER_ID,
        "local": snapshot_local_users(),
        "remote": snapshot_remote_users(),
    }


async def _broadcast(frame_type: str, payload: Dict[str, Any]) -> None:
    """Send a presence update through the router if broadcasting is enabled."""
    sender = _BROADCAST
    if not sender:
        return
    try:
        await sender(frame_type, payload)
    except Exception:
        log.exception("presence broadcast failed")


async def on_user_local_join(user_id: str, meta: Optional[Dict[str, Any]] = None) -> None:
    """Remember a freshly connected user and announce their arrival."""
    meta = meta or {}
    if user_id in _LOCAL_META:
        _LOCAL_META[user_id].update(meta)
    else:
        _LOCAL_META[user_id] = meta.copy()
    router.note_local_user(user_id)
    await _broadcast(
        "USER_ADVERTISE",
        {
            "server_id": _SERVER_ID,
            "user": user_id,
            "meta": meta,
        },
    )
    log.info("Advertise user join: %s", user_id)


async def on_user_local_leave(user_id: str) -> None:
    """Remove a departing local user and gossip the departure to peers."""
    _LOCAL_META.pop(user_id, None)
    router.drop_local_user(user_id)
    await _broadcast(
        "USER_REMOVE",
        {
            "server_id": _SERVER_ID,
            "user": user_id,
        },
    )
    log.info("Advertise user leave: %s", user_id)


def handle_remote_join(server_id: str, user_id: str, meta: Optional[Dict[str, Any]] = None) -> None:
    """Record that a peer server can deliver messages for a user."""
    meta = meta or {}
    server_view = _REMOTE_META.setdefault(server_id, {})
    server_view[user_id] = meta.copy()
    router.note_remote_user(server_id, user_id)
    log.info("Remote user %s now reachable via %s", user_id, server_id)


def handle_remote_leave(server_id: str, user_id: str) -> None:
    """Drop a remote user mapping when the authoritative server removes them."""
    if router.USER_LOCATION.get(user_id) != server_id:
        log.debug(
            "Ignoring USER_REMOVE for %s from %s; current mapping is %s",
            user_id,
            server_id,
            router.USER_LOCATION.get(user_id),
        )
        return
    server_view = _REMOTE_META.get(server_id)
    if server_view and user_id in server_view:
        server_view.pop(user_id, None)
        if not server_view:
            _REMOTE_META.pop(server_id, None)
    router.drop_remote_user(user_id, server_id)
    public.handle_remote_leave(server_id, user_id)
    log.info("Remote user %s left %s", user_id, server_id)


def handle_remote_snapshot(server_id: str, users: Dict[str, Dict[str, Any]]) -> None:
    """Refresh our presence view using the latest list from a peer server."""
    existing = _REMOTE_META.setdefault(server_id, {})
    existing.clear()
    for user, meta in users.items():
        existing[user] = meta.copy()
        router.note_remote_user(server_id, user)
    # Drop any mapping that is no longer present
    for user in list(router.REMOTE_USERS.get(server_id, set())):
        if user not in existing:
            router.drop_remote_user(user, server_id)
    public.handle_remote_snapshot(server_id, existing)


def handle_remote_disconnect(server_id: str) -> None:
    """Forget every remote user when we lose the connection to a server."""
    _REMOTE_META.pop(server_id, None)
    router.drop_remote_server(server_id)
    public.handle_remote_disconnect(server_id)
    log.warning("Peer %s disconnected; remote users unavailable", server_id)
