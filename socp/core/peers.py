import asyncio
import json
import logging
import pathlib
import time
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional

import websockets

log = logging.getLogger("socp.peers")

_LOCAL_ID = "unknown"
_SHARED_SECRET = ""
_PEER_CONFIG: Dict[str, Dict[str, Any]] = {}
_PEER_KEYS: Dict[str, bytes] = {}
_ACTIVE: Dict[str, Any] = {}
_TASKS: Dict[str, asyncio.Task] = {}
_FRAME_HANDLER: Optional[Callable[[Any, str], Awaitable[None]]] = None
_DISCONNECT_HANDLER: Optional[Callable[[str], Awaitable[None]]] = None
_HELLO_PROVIDER: Optional[Callable[[], Dict[str, Any]]] = None
_HELLO_BUILDER: Optional[Callable[[str, Dict[str, Any], Dict[str, Any]], Any]] = None
_RECONNECT_DELAY = 5.0


class ClientLink:
    def __init__(self, websocket):
        self.ws = websocket
        self.peer_id: Optional[str] = None
        self.kind = "server"

    async def send(self, frame: Any) -> None:
        if isinstance(frame, str):
            payload = frame
        else:
            payload = json.dumps(frame, separators=(",", ":"))
        await self.ws.send(payload)


def _load_key_blob(value: Optional[str]) -> Optional[bytes]:
    if not value:
        return None
    if "BEGIN" in value:
        return value.encode("utf-8")
    try:
        path = pathlib.Path(value).expanduser().resolve()
        if path.is_file():
            return path.read_bytes()
    except Exception:
        log.exception("failed to load peer key from %s", value)
    return None


def _prepare_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    data = dict(entry)
    if "uri" not in data:
        host = data.get("host")
        port = data.get("port")
        if host and port:
            data["uri"] = f"ws://{host}:{port}"
    data["introducer"] = bool(data.get("introducer", False))
    key_blob = data.get("public_key")
    if key_blob:
        loaded = _load_key_blob(key_blob if isinstance(key_blob, str) else None)
        if loaded:
            data["public_key_bytes"] = loaded
    return data


def add_peer_entry(entry: Dict[str, Any]) -> None:
    pid = entry.get("server_id")
    if not pid or pid == _LOCAL_ID:
        return
    prepared = _prepare_entry(entry)
    existing = _PEER_CONFIG.get(pid)
    if existing is None:
        _PEER_CONFIG[pid] = prepared
    else:
        existing.update(prepared)
        prepared = existing
    key_bytes = prepared.get("public_key_bytes")
    if key_bytes:
        _PEER_KEYS[pid] = key_bytes
    if pid not in _TASKS:
        _TASKS[pid] = asyncio.create_task(_maintain_peer(pid))


def add_peer_entries(entries: Iterable[Dict[str, Any]]) -> None:
    for entry in entries or []:
        if isinstance(entry, dict):
            add_peer_entry(entry)


async def _maintain_peer(server_id: str) -> None:
    while True:
        entry = _PEER_CONFIG.get(server_id)
        if entry is None:
            await asyncio.sleep(_RECONNECT_DELAY)
            continue
        uri = entry.get("uri") or f"ws://{entry['host']}:{entry['port']}"
        if server_id in _ACTIVE:
            await asyncio.sleep(_RECONNECT_DELAY)
            continue
        try:
            ws = await websockets.connect(uri)
            link = ClientLink(ws)
            link.peer_id = server_id
            _ACTIVE[server_id] = link
            log.info("Connected to peer %s (%s)", server_id, uri)
            await _send_hello(link, entry)
            async for message in ws:
                handler = _FRAME_HANDLER
                if handler:
                    await handler(link, message)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Peer connection to %s failed", server_id)
        finally:
            _ACTIVE.pop(server_id, None)
            task = _TASKS.get(server_id)
            if task and task.done():
                _TASKS.pop(server_id, None)
            if _DISCONNECT_HANDLER:
                try:
                    await _DISCONNECT_HANDLER(server_id)
                except Exception:
                    log.exception("disconnect handler for %s raised", server_id)
        await asyncio.sleep(_RECONNECT_DELAY)


async def _send_hello(link: ClientLink, entry: Dict[str, Any]) -> None:
    users = {}
    if _HELLO_PROVIDER:
        try:
            users = _HELLO_PROVIDER() or {}
        except Exception:
            log.exception("hello provider failed")
            users = {}
    builder = _HELLO_BUILDER
    if builder:
        frame = builder(entry.get("server_id", ""), users, entry)
        if frame:
            await link.send(frame)
            return
    control_type = "SERVER_HELLO_JOIN" if entry.get("introducer") else "SERVER_ANNOUNCE"
    fallback = {
        "control": control_type,
        "server_id": _LOCAL_ID,
        "secret": _SHARED_SECRET,
        "users": users,
        "ts": int(time.time()),
    }
    uri = entry.get("uri")
    if uri:
        fallback["uri"] = uri
    await link.send(fallback)


async def bootstrap(
    local_id: str,
    shared_secret: str,
    peer_entries: Optional[Iterable[Dict[str, Any]]],
    frame_handler: Callable[[Any, str], Awaitable[None]],
    disconnect_handler: Callable[[str], Awaitable[None]],
    hello_provider: Callable[[], Dict[str, Any]],
    hello_builder: Optional[Callable[[str, Dict[str, Any], Dict[str, Any]], Any]] = None,
) -> None:
    global _LOCAL_ID, _SHARED_SECRET, _FRAME_HANDLER, _DISCONNECT_HANDLER, _HELLO_PROVIDER, _HELLO_BUILDER
    _LOCAL_ID = local_id or _LOCAL_ID
    _SHARED_SECRET = shared_secret
    _FRAME_HANDLER = frame_handler
    _DISCONNECT_HANDLER = disconnect_handler
    _HELLO_PROVIDER = hello_provider
    _HELLO_BUILDER = hello_builder
    add_peer_entries(peer_entries)


def set_local_id(server_id: str) -> None:
    global _LOCAL_ID
    if server_id:
        _LOCAL_ID = server_id


def get_shared_secret() -> str:
    return _SHARED_SECRET


def track_incoming(server_id: str, link: Any) -> None:
    if server_id:
        _ACTIVE[server_id] = link


def current_peers() -> Dict[str, Any]:
    return dict(_ACTIVE)


async def broadcast_control(message: Dict[str, Any]) -> None:
    for server_id, link in list(_ACTIVE.items()):
        try:
            await link.send(message)
        except Exception:
            log.exception("broadcast to %s failed", server_id)


async def send_to(server_id: str, message: Any) -> bool:
    link = _ACTIVE.get(server_id)
    if not link:
        link = await ensure_connected(server_id)
        if not link:
            return False
    try:
        await link.send(message)
        return True
    except Exception:
        log.exception("send to %s failed", server_id)
        return False


async def ensure_connected(server_id: str, timeout: float = 5.0) -> Optional[Any]:
    if server_id in _ACTIVE:
        return _ACTIVE[server_id]
    entry = _PEER_CONFIG.get(server_id)
    if not entry:
        return None
    if server_id not in _TASKS:
        _TASKS[server_id] = asyncio.create_task(_maintain_peer(server_id))
    deadline = time.time() + timeout
    while time.time() < deadline:
        link = _ACTIVE.get(server_id)
        if link:
            return link
        await asyncio.sleep(0.2)
    return _ACTIVE.get(server_id)


async def shutdown() -> None:
    for task in list(_TASKS.values()):
        task.cancel()
    _TASKS.clear()
    for link in list(_ACTIVE.values()):
        try:
            await link.ws.close()
        except Exception:
            pass
    _ACTIVE.clear()


def get_config(server_id: str) -> Optional[Dict[str, Any]]:
    entry = _PEER_CONFIG.get(server_id)
    return dict(entry) if entry else None


def merge_peer_configs(entries: Iterable[Dict[str, Any]]) -> None:
    add_peer_entries(entries)


def forget(server_id: str) -> None:
    _ACTIVE.pop(server_id, None)


def known_peers() -> Dict[str, Dict[str, Any]]:
    return {sid: dict(cfg) for sid, cfg in _PEER_CONFIG.items()}


def set_peer_key(server_id: str, pem_bytes: bytes) -> None:
    if server_id and pem_bytes:
        _PEER_KEYS[server_id] = pem_bytes


def get_peer_key(server_id: str) -> Optional[bytes]:
    return _PEER_KEYS.get(server_id)


__all__ = [
    "ClientLink",
    "add_peer_entry",
    "add_peer_entries",
    "bootstrap",
    "broadcast_control",
    "current_peers",
    "ensure_connected",
    "forget",
    "get_config",
    "get_shared_secret",
    "get_peer_key",
    "known_peers",
    "merge_peer_configs",
    "send_to",
    "set_peer_key",
    "set_local_id",
    "shutdown",
    "track_incoming",
]
