import argparse
import asyncio
import base64
import json
import logging
import os
import ssl
import time
from collections import defaultdict
from typing import Any, Dict, Iterable, Optional

import yaml

from socp.core import crypto, files, peers, presence, proto, public, router, store, ws
from socp.core.proto import Envelope

log = logging.getLogger("socp.server")

CLOCK_SKEW_MS = 120_000
MAX_AGE_MS = 300_000
HEARTBEAT_INTERVAL = 15
HEARTBEAT_TIMEOUT_MS = 45_000
DEFAULT_SHARED_SECRET = "socp-shared-secret"

ACTIVE: dict[str, set] = defaultdict(set)
LOCAL_SERVER_ID = "unknown"
LOCAL_URI = ""
SHARED_SECRET = DEFAULT_SHARED_SECRET
SSL_CONTEXT: Optional[ssl.SSLContext] = None

SERVER_PRIVATE_PEM: bytes = b""
SERVER_PUBLIC_PEM: bytes = b""
SERVER_PUBLIC_TEXT: str = ""

BACKGROUND_TASKS: list[asyncio.Task] = []
PEER_LAST_SEEN: dict[str, int] = {}

SERVER_MESSAGE_TYPES = {
    "SERVER_HELLO_JOIN",
    "SERVER_WELCOME",
    "SERVER_ANNOUNCE",
    "SERVER_DELIVER",
    "SERVER_HEARTBEAT",
    "SERVER_HEARTBEAT_ACK",
    "USER_ADVERTISE",
    "USER_REMOVE",
    "USER_LIST_RESPONSE",
    "PUBLIC_CHANNEL_ADD",
    "PUBLIC_CHANNEL_UPDATED",
    "PUBLIC_CHANNEL_KEY_SHARE",
}

USER_DIRECT_TYPES = {"MSG_DIRECT", "USER_MESSAGE"}


def _now_ms() -> int:
    """Return the current time in milliseconds."""
    return int(time.time() * 1000)


def _load_key_material(value: Optional[str]) -> bytes:
    """Load PEM key material either from inline text or a file path."""
    if not value:
        raise ValueError("key path or value not provided")
    if "BEGIN" in value:
        return value.encode("utf-8")
    path = os.path.expanduser(value)
    with open(path, "rb") as fh:
        return fh.read()


def _load_server_keys(cfg: Dict[str, Any]) -> None:
    """Read the configured server key pair into module-level caches."""
    global SERVER_PRIVATE_PEM, SERVER_PUBLIC_PEM, SERVER_PUBLIC_TEXT
    priv_path = cfg.get("server_private_key")
    pub_path = cfg.get("server_public_key")
    if not priv_path or not pub_path:
        raise RuntimeError("server_private_key and server_public_key must be set in the config")
    SERVER_PRIVATE_PEM = _load_key_material(priv_path)
    SERVER_PUBLIC_PEM = _load_key_material(pub_path)
    SERVER_PUBLIC_TEXT = SERVER_PUBLIC_PEM.decode("utf-8")


def _error_frame(code: str, reason: str, ref: Optional[str] = None) -> Dict[str, Any]:
    """Build an unsigned error frame so we can reply in failure scenarios."""
    return {
        "type": "ERROR",
        "from": LOCAL_SERVER_ID,
        "to": None,
        "ts": _now_ms(),
        "payload": {"code": code, "reason": reason, "ref": ref},
        "sig": "",
    }


def _encode_frame(frame: Dict[str, Any]) -> Dict[str, Any]:
    """Convert any byte signatures into base64 strings for transport."""
    if "sig" in frame and isinstance(frame["sig"], bytes):
        frame["sig"] = base64.b64encode(frame["sig"]).decode("ascii")
    return frame


def _sign_frame(frame: Dict[str, Any]) -> Dict[str, Any]:
    """Attach the server's RSA signature to a frame."""
    body = proto.canonical_bytes(frame)
    sig = crypto.sign_pss_sha256(SERVER_PRIVATE_PEM, body)
    frame["sig"] = base64.b64encode(sig).decode("ascii")
    return frame


def _build_server_frame(frame_type: str, to: str | None, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Create and sign a frame destined for another server."""
    frame = proto.build_frame(frame_type, LOCAL_SERVER_ID, to or "*", payload)
    return _sign_frame(frame)


def _build_user_frame(frame_type: str, to: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Create and sign a frame destined for a local user."""
    frame = proto.build_frame(frame_type, LOCAL_SERVER_ID, to, payload)
    return _sign_frame(frame)


async def _send_server_frame(dest: str, frame_type: str, payload: Dict[str, Any]) -> bool:
    """Send a signed frame to another server if we currently know the peer."""
    frame = _build_server_frame(frame_type, dest, payload)
    return await peers.send_to(dest, frame)


async def _broadcast_server_frame(frame_type: str, payload: Dict[str, Any], *, exclude: Optional[Iterable[str]] = None) -> None:
    """Send a server frame to every connected peer, optionally skipping some."""
    excluded = set(exclude or [])
    for server_id in list(peers.known_peers().keys()):
        if server_id == LOCAL_SERVER_ID or server_id in excluded:
            continue
        await _send_server_frame(server_id, frame_type, payload)


async def _presence_broadcast(frame_type: str, payload: Dict[str, Any]) -> None:
    """Wrapper used by presence.py so it can reuse our broadcast helper."""
    await _broadcast_server_frame(frame_type, payload)


async def _heartbeat_loop() -> None:
    """Periodically ping peers and prune the ones that stop responding."""
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        now = _now_ms()
        payload = {"ts": now}
        await _broadcast_server_frame("SERVER_HEARTBEAT", payload)
        await _enforce_heartbeat_timeouts(now)


async def _enforce_heartbeat_timeouts(now_ms: int) -> None:
    """Close connections to peers that have not answered recent heartbeats."""
    expired: list[str] = []
    for server_id, last_seen in list(PEER_LAST_SEEN.items()):
        if now_ms - last_seen > HEARTBEAT_TIMEOUT_MS:
            expired.append(server_id)
    if not expired:
        return
    active = peers.current_peers()
    for server_id in expired:
        link = active.get(server_id)
        if link and hasattr(link, "ws"):
            try:
                await link.ws.close(code=4000, reason="heartbeat timeout")
            except Exception:
                pass
        peers.forget(server_id)
        presence.handle_remote_disconnect(server_id)
        PEER_LAST_SEEN.pop(server_id, None)
        log.warning("Peer %s timed out due to heartbeat inactivity", server_id)


def _ensure_peer_info(server_id: str, payload: Dict[str, Any]) -> None:
    """Update our peer directory cache using details from a frame."""
    if not server_id:
        return
    uri = payload.get("uri")
    if uri:
        peers.add_peer_entry({"server_id": server_id, "uri": uri})
        router.note_remote_server(server_id, uri)
    server_pub = payload.get("server_pub")
    if isinstance(server_pub, str) and "BEGIN" in server_pub:
        peers.set_peer_key(server_id, server_pub.encode("utf-8"))


def _peer_directory() -> list[Dict[str, Any]]:
    """Return introducer-style records for every peer we know."""
    directory: list[Dict[str, Any]] = []
    for server_id, cfg in peers.known_peers().items():
        entry = dict(cfg)
        key = peers.get_peer_key(server_id)
        if key:
            entry["public_key"] = key.decode("utf-8")
        directory.append(entry)
    return directory


def _decode_base64(value: str, label: str) -> bytes:
    """Decode a base64 field and raise a friendly error on failure."""
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"{label} invalid base64") from exc


def _verify_server_envelope(env: Envelope) -> Optional[str]:
    """Check that a server-signed envelope carries a valid signature."""
    server_id = env.from_
    payload = env.payload if isinstance(env.payload, dict) else {}
    if server_id:
        _ensure_peer_info(server_id, payload)
    key = peers.get_peer_key(server_id)
    if not key:
        return "SERVER_KEY_UNKNOWN"
    if not isinstance(env.sig, str) or not env.sig:
        return "SERVER_SIG_MISSING"
    try:
        sig_bytes = base64.b64decode(env.sig, validate=True)
    except Exception:
        return "SERVER_SIG_FORMAT"
    body = proto.canonical_bytes(env)
    if not crypto.verify_pss_sha256(key, body, sig_bytes):
        return "SERVER_SIG_INVALID"
    return None


async def _register_user_link(link, env: Envelope, meta_hint: Optional[Dict[str, Any]]) -> None:
    """Associate a websocket link with a user id and gossip their presence."""
    links = ACTIVE[env.from_]
    first = len(links) == 0
    links.add(link)
    link.kind = "user"
    setattr(link, "_socp_user", env.from_)
    if first:
        await presence.on_user_local_join(env.from_, meta_hint or {})
    log.info("bound link to user=%s (connections=%d)", env.from_, len(links))


def _decode_chunk(payload: Dict[str, Any]) -> tuple[str, int, bytes, Dict[str, Any]]:
    """Extract and validate fields from a FILE_CHUNK payload."""
    file_id = payload.get("file_id") or payload.get("manifest", {}).get("file_id")
    if not isinstance(file_id, str):
        raise ValueError("file_id missing")
    chunk_index = payload.get("chunk_index")
    if not isinstance(chunk_index, int):
        raise ValueError("chunk_index missing")
    chunk_b64 = payload.get("chunk")
    if not isinstance(chunk_b64, str):
        raise ValueError("chunk missing")
    chunk_bytes = _decode_base64(chunk_b64, "chunk")
    manifest = payload.get("manifest")
    if not isinstance(manifest, dict):
        raise ValueError("manifest missing")
    manifest.setdefault("file_id", file_id)
    return file_id, chunk_index, chunk_bytes, manifest


async def _notify_local_file_ready(recipient, manifest: Dict[str, Any], info: Dict[str, Any]) -> None:
    """Tell a waiting local user that their file finished processing."""
    if recipient is None:
        return
    target = str(recipient)
    links = ACTIVE.get(target)
    if not links:
        return
    payload = {
        "file_id": manifest.get("file_id"),
        "name": manifest.get("name"),
        "size": manifest.get("size"),
        "path": info.get("path"),
        "status": info.get("status"),
    }
    for link in list(links):
        try:
            await link.send({"type": "SERVER_FILE_READY", "payload": payload})
        except Exception:
            links.discard(link)


def _is_local_destination(target) -> bool:
    """Return True if the intended recipient is hosted on this server."""
    if target is None:
        return True
    dest = router.lookup_destination(str(target))
    return dest in (None, "local")


async def _handle_file_flow(env: Envelope, link) -> bool:
    """Process inbound file-transfer frames, returning True when handled."""
    payload = env.payload if isinstance(env.payload, dict) else {}
    if env.type == "FILE_START":
        if not _is_local_destination(env.to):
            return False
        manifest = payload.get("manifest") if isinstance(payload.get("manifest"), dict) else payload
        manifest = dict(manifest)
        file_id = manifest.get("file_id") or payload.get("file_id")
        if not isinstance(file_id, str):
            await link.send({"type": "FILE_STATUS", "payload": {"status": "error", "reason": "file_id missing"}})
            return True
        manifest["file_id"] = file_id
        try:
            res = files.begin_file_transfer(file_id, manifest, sender=env.from_)
            await link.send({"type": "FILE_STATUS", "payload": {"file_id": file_id, **res}})
        except Exception as exc:
            await link.send({"type": "FILE_STATUS", "payload": {"status": "error", "reason": str(exc)}})
        return True
    if env.type == "FILE_CHUNK":
        if not _is_local_destination(env.to):
            return False
        try:
            file_id, chunk_idx, chunk_bytes, manifest = _decode_chunk(payload)
            res = files.accept_file_chunk(file_id, chunk_idx, chunk_bytes, manifest, env.from_)
            await link.send({"type": "FILE_STATUS", "payload": {"file_id": file_id, **res}})
        except Exception as exc:
            await link.send({"type": "FILE_STATUS", "payload": {"status": "error", "reason": str(exc)}})
        return True
    if env.type == "FILE_END":
        if not _is_local_destination(env.to):
            return False
        manifest = payload if isinstance(payload, dict) else {}
        file_id = manifest.get("file_id")
        if not isinstance(file_id, str):
            await link.send({"type": "FILE_STATUS", "payload": {"status": "error", "reason": "file_id missing"}})
            return True
        try:
            info = files.complete_file_transfer(file_id, manifest)
            await link.send({"type": "FILE_STATUS", "payload": info})
            await _notify_local_file_ready(env.to, manifest, info)
        except Exception as exc:
            await link.send({"type": "FILE_STATUS", "payload": {"status": "error", "reason": str(exc)}})
        return True
    return False


async def _send_to_user_links(user: str, frame: Dict[str, Any]) -> int:
    """Send a frame to every websocket currently bound to the given user."""
    links = ACTIVE.get(user)
    if not links:
        return 0
    delivered = 0
    for lnk in list(links):
        try:
            await lnk.send(frame)
            delivered += 1
        except Exception:
            links.discard(lnk)
    if not links:
        ACTIVE.pop(user, None)
    return delivered


async def _deliver_local(env: Envelope) -> int:
    """Deliver an envelope to local clients and return how many got it."""
    payload = {"envelope": env.to_dict()}
    if env.to is None or (isinstance(env.to, str) and env.to.lower() in {"public", "__public__", "all"}):
        delivered = 0
        for uname in list(ACTIVE.keys()):
            frame = _build_user_frame("USER_DELIVER", uname, payload)
            delivered += await _send_to_user_links(uname, frame)
        return delivered
    target = str(env.to)
    frame = _build_user_frame("USER_DELIVER", target, payload)
    return await _send_to_user_links(target, frame)


async def _forward(env: Envelope) -> bool:
    """Relay an envelope to the appropriate remote server if needed."""
    if env.to is None or (isinstance(env.to, str) and env.to.lower() in {"public", "__public__", "all"}):
        success = False
        for server_id in list(peers.known_peers().keys()):
            if server_id == LOCAL_SERVER_ID:
                continue
            frame = _build_server_frame(
                "SERVER_DELIVER",
                server_id,
                {"envelope": env.to_dict()},
            )
            sent = await peers.send_to(server_id, frame)
            success = success or sent
        return success
    target = router.lookup_destination(str(env.to))
    if not target or target == "local":
        return False
    frame = _build_server_frame(
        "SERVER_DELIVER",
        target,
        {"envelope": env.to_dict()},
    )
    await peers.ensure_connected(target)
    return await peers.send_to(target, frame)


async def _lookup_pubkey(username: str) -> Optional[bytes]:
    """Grab a user's public key from the store or crypto helpers."""
    getter = getattr(store, "get_user_pubkey", None)
    if callable(getter):
        try:
            result = await getter(username) if asyncio.iscoroutinefunction(getter) else getter(username)
            if result:
                return result if isinstance(result, bytes) else str(result).encode("utf-8")
        except Exception:
            log.exception("store.get_user_pubkey failed")
    peers_getter = getattr(crypto, "get_pubkey", None)
    if callable(peers_getter):
        try:
            result = await peers_getter(username) if asyncio.iscoroutinefunction(peers_getter) else peers_getter(username)
            if result:
                return result if isinstance(result, bytes) else str(result).encode("utf-8")
        except Exception:
            log.exception("peers crypto get_pubkey failed")
    return None


async def _verify_user_envelope(env: Envelope) -> tuple[Optional[str], Optional[bytes]]:
    """Check a user envelope signature and return an error string if any."""
    pub = await _lookup_pubkey(env.from_)
    if not pub:
        return "NOT_TRUSTED", None
    err = _verify_signature_with_key(env, pub)
    if err:
        return err, None
    return None, pub


def _verify_signature_with_key(env: Envelope, pub: bytes) -> Optional[str]:
    """Verify the envelope signature with the provided public key."""
    if not isinstance(env.sig, str) or not env.sig:
        return "SIG_REQUIRED"
    try:
        sig_bytes = base64.b64decode(env.sig, validate=True)
    except Exception:
        return "SIG_FORMAT"
    msg = proto.canonical_bytes(env)
    if not crypto.verify_pss_sha256(pub, msg, sig_bytes):
        return "SIG_BAD"
    return None


def _verify_user_message_content(env: Envelope, pub: bytes) -> Optional[str]:
    """Ensure a MSG_DIRECT payload includes a signed content blob."""
    if env.type not in USER_DIRECT_TYPES:
        return None
    payload = env.payload if isinstance(env.payload, dict) else {}
    content_b64 = payload.get("content")
    sig_b64 = payload.get("content_sig")
    if not isinstance(content_b64, str) or not isinstance(sig_b64, str):
        return "CONTENT_SIG_REQUIRED"
    content_bytes = _decode_base64(content_b64, "content")
    sig_bytes = _decode_base64(sig_b64, "content_sig")
    if not crypto.verify_pss_sha256(pub, content_bytes, sig_bytes):
        return "CONTENT_SIG_INVALID"
    return None


def _parse_user_hello_payload(payload: Dict[str, Any]) -> tuple[str, bytes, Optional[str], Dict[str, Any]]:
    """Validate and normalise fields included in USER_HELLO."""
    if not isinstance(payload, dict):
        raise ValueError("USER_HELLO payload must be an object")
    client = payload.get("client")
    if not isinstance(client, str) or not client.strip():
        raise ValueError("client identifier required")
    pubkey = payload.get("pubkey")
    if not isinstance(pubkey, str) or "BEGIN" not in pubkey:
        raise ValueError("pubkey must be a PEM string")
    enc_pubkey = payload.get("enc_pubkey")
    if enc_pubkey is not None and not isinstance(enc_pubkey, str):
        raise ValueError("enc_pubkey must be a string when provided")
    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
    return client.strip(), pubkey.encode("utf-8"), enc_pubkey, dict(meta)


async def _handle_user_hello(env: Envelope, link, payload: Dict[str, Any]) -> None:
    """Finish binding a websocket to a user after a successful USER_HELLO."""
    existing_binding = getattr(link, "_socp_user", None)
    if existing_binding and existing_binding != env.from_:
        await link.send(_error_frame("BAD_USER", "Link already bound to another user"))
        return
    try:
        client_name, pubkey_bytes, enc_pubkey, meta = _parse_user_hello_payload(payload)
    except ValueError as exc:
        await link.send(_error_frame("BAD_HELLO", str(exc)))
        return
    if not crypto.accept_pubkey(pubkey_bytes):
        await link.send(_error_frame("BAD_KEY", "Public key rejected"))
        return
    known_key = await _lookup_pubkey(env.from_)
    if known_key and known_key != pubkey_bytes:
        await link.send(_error_frame("NAME_IN_USE", "User already registered with different key"))
        return
    sig_err = _verify_signature_with_key(env, pubkey_bytes)
    if sig_err:
        await link.send(_error_frame("BAD_SIG", sig_err))
        return
    meta_payload = dict(meta)
    meta_payload.setdefault("client", client_name)
    if enc_pubkey:
        meta_payload["enc_pubkey"] = enc_pubkey
    await store.upsert_user(env.from_, pubkey_bytes, meta=meta_payload)
    await _register_user_link(link, env, meta_payload)
    welcome_frame = _build_user_frame(
        "USER_WELCOME",
        env.from_,
        {"server_id": LOCAL_SERVER_ID},
    )
    await _send_to_user_links(env.from_, welcome_frame)
    share_payload, gossip_payload = await public.add_local_member(env.from_, pubkey_bytes)
    if share_payload:
        share_frame = _build_user_frame("PUBLIC_CHANNEL_KEY_SHARE", env.from_, share_payload)
        await _send_to_user_links(env.from_, share_frame)
    if gossip_payload:
        gossip_payload.setdefault("server_id", LOCAL_SERVER_ID)
        await _broadcast_server_frame("PUBLIC_CHANNEL_ADD", gossip_payload)
        await _broadcast_server_frame("PUBLIC_CHANNEL_UPDATED", public.snapshot())
    ack = _build_user_frame("ACK", env.from_, {"hello": True, "server_id": LOCAL_SERVER_ID})
    await _send_to_user_links(env.from_, ack)


async def _handle_server_envelope(env: Envelope, link) -> None:
    """Process frames that arrived from another server."""
    payload = env.payload if isinstance(env.payload, dict) else {}
    server_id = env.from_
    if isinstance(server_id, str) and server_id:
        PEER_LAST_SEEN[server_id] = _now_ms()
    if env.type == "SERVER_HELLO_JOIN":
        secret = payload.get("secret")
        if secret != SHARED_SECRET:
            await link.send(_error_frame("AUTH_FAILED", "Shared secret mismatch"))
            await link.ws.close(code=4003)
            return
        peers.track_incoming(server_id, link)
        _ensure_peer_info(server_id, payload)
        users = payload.get("users") if isinstance(payload.get("users"), dict) else {}
        presence.handle_remote_snapshot(server_id, users or {})
        welcome_payload = {
            "users": presence.snapshot_local_users(),
            "peers": _peer_directory(),
            "server_pub": SERVER_PUBLIC_TEXT,
            "uri": LOCAL_URI,
        }
        await _send_server_frame(server_id, "SERVER_WELCOME", welcome_payload)
        return
    if env.type == "SERVER_WELCOME":
        assigned = payload.get("assigned_id")
        if isinstance(assigned, str) and assigned:
            _update_local_server_id(assigned)
        _ensure_peer_info(server_id, payload)
        peers.track_incoming(server_id, link)
        users = payload.get("users") if isinstance(payload.get("users"), dict) else {}
        presence.handle_remote_snapshot(server_id, users or {})
        peers.merge_peer_configs(payload.get("peers") or [])
        await _broadcast_server_frame(
            "SERVER_ANNOUNCE",
            {
                "server_id": LOCAL_SERVER_ID,
                "users": presence.snapshot_local_users(),
                "uri": LOCAL_URI,
                "server_pub": SERVER_PUBLIC_TEXT,
            },
            exclude={server_id},
        )
        return
    if env.type == "SERVER_ANNOUNCE":
        announced_id = payload.get("server_id") or server_id
        if isinstance(announced_id, str):
            peers.add_peer_entry({"server_id": announced_id, "uri": payload.get("uri")})
            router.note_remote_server(announced_id, payload.get("uri"))
            server_pub = payload.get("server_pub")
            if isinstance(server_pub, str) and "BEGIN" in server_pub:
                peers.set_peer_key(announced_id, server_pub.encode("utf-8"))
            users = payload.get("users") if isinstance(payload.get("users"), dict) else {}
            presence.handle_remote_snapshot(announced_id, users or {})
        return
    if env.type == "SERVER_DELIVER":
        inner = payload.get("envelope")
        if isinstance(inner, dict):
            try:
                inner_env = Envelope(**inner)
            except ValueError:
                return
            await _process_envelope(inner_env, link, forwarded=True)
        return
    if env.type == "SERVER_HEARTBEAT":
        await _send_server_frame(server_id, "SERVER_HEARTBEAT_ACK", {"ts": _now_ms()})
        return
    if env.type == "SERVER_HEARTBEAT_ACK":
        return
    if env.type == "USER_ADVERTISE":
        presence.handle_remote_join(payload.get("server_id"), payload.get("user"), payload.get("meta"))
        return
    if env.type == "USER_REMOVE":
        presence.handle_remote_leave(payload.get("server_id"), payload.get("user"))
        return
    if env.type == "USER_LIST_RESPONSE":
        server_id = payload.get("server_id") or env.from_
        users = payload.get("users") if isinstance(payload.get("users"), dict) else {}
        local_users = users.get("local") if isinstance(users.get("local"), dict) else {}
        if isinstance(server_id, str):
            presence.handle_remote_snapshot(server_id, local_users)
        return
    if env.type == "PUBLIC_CHANNEL_ADD":
        public.handle_remote_add(payload)
        return
    if env.type == "PUBLIC_CHANNEL_UPDATED":
        payload = dict(payload)
        payload.setdefault("server_id", server_id)
        public.handle_remote_update(payload)
        return
    if env.type == "PUBLIC_CHANNEL_KEY_SHARE":
        share = public.handle_remote_key_share(payload)
        if share:
            target_user = payload.get("user")
            if isinstance(target_user, str):
                frame = _build_user_frame("PUBLIC_CHANNEL_KEY_SHARE", target_user, share)
                await _send_to_user_links(target_user, frame)
        return
    log.warning("Unhandled server envelope type %s", env.type)


def _update_local_server_id(server_id: str) -> None:
    """Refresh globals when the introducer assigns us a server id."""
    global LOCAL_SERVER_ID
    if server_id and server_id != LOCAL_SERVER_ID:
        LOCAL_SERVER_ID = server_id
        router.configure(LOCAL_SERVER_ID)
        presence.configure(LOCAL_SERVER_ID, _presence_broadcast)
        peers.set_local_id(LOCAL_SERVER_ID)
    public.configure(LOCAL_SERVER_ID)


async def _handle_peer_disconnect(server_id: str) -> None:
    """Callback for peers.bootstrap when a remote server link drops."""
    if server_id:
        peers.forget(server_id)
        presence.handle_remote_disconnect(server_id)
        PEER_LAST_SEEN.pop(server_id, None)


async def _on_disconnect(link) -> None:
    """Shared websocket disconnect hook for both users and servers."""
    kind = getattr(link, "kind", None)
    if kind == "user":
        user = getattr(link, "_socp_user", None)
        if user:
            links = ACTIVE.get(user)
            if links:
                links.discard(link)
                if not links:
                    ACTIVE.pop(user, None)
                    await presence.on_user_local_leave(user)
                    removal = await public.remove_local_member(user)
                    if removal:
                        await _broadcast_server_frame("PUBLIC_CHANNEL_UPDATED", public.snapshot())
    elif kind == "server":
        server_id = getattr(link, "peer_id", None)
        if server_id:
            peers.forget(server_id)
            presence.handle_remote_disconnect(server_id)
            elif getattr(link, "kind", None) == "server":
                server_id = getattr(link, "peer_id", None)
                if server_id:
                    peers.forget(server_id)
                    presence.handle_remote_disconnect(server_id)
            PEER_LAST_SEEN.pop(server_id, None)


def _hello_builder(target_server_id: str, users: Dict[str, Any], entry: Dict[str, Any]) -> Dict[str, Any]:
    """Helper passed to peers.bootstrap to construct hello/announce frames."""
    frame_type = "SERVER_HELLO_JOIN" if entry.get("introducer") else "SERVER_ANNOUNCE"
    payload = {
        "secret": SHARED_SECRET,
        "users": users,
        "uri": LOCAL_URI,
        "server_pub": SERVER_PUBLIC_TEXT,
    }
    return _build_server_frame(frame_type, target_server_id or entry.get("server_id"), payload)


async def _process_envelope(env: Envelope, link, *, forwarded: bool = False) -> None:
    """Core router that handles every inbound envelope from a websocket."""
    ts_err = None
    if not isinstance(env.ts, int):
        ts_err = "TS_TYPE"
    else:
        now = _now_ms()
        if env.ts > now + CLOCK_SKEW_MS:
            ts_err = "TS_IN_FUTURE"
        elif now - env.ts > MAX_AGE_MS:
            ts_err = "TS_TOO_OLD"
    if ts_err:
        if not forwarded:
            await link.send(_error_frame("BAD_TS", ts_err))
        return

    if env.type in SERVER_MESSAGE_TYPES:
        sig_err = _verify_server_envelope(env)
        if sig_err:
            await link.send(_error_frame("BAD_SIG", sig_err))
            return
        await _handle_server_envelope(env, link)
        return

    payload_obj = env.payload if isinstance(env.payload, dict) else {}

    if env.type == "USER_HELLO" and not forwarded and getattr(link, "kind", None) != "server":
        await _handle_user_hello(env, link, payload_obj)
        return

    if not forwarded and getattr(link, "kind", None) != "server":
        bound_user = getattr(link, "_socp_user", None)
        if bound_user is None:
            await link.send(_error_frame("HELLO_REQUIRED", "USER_HELLO required before messaging"))
            return
        if bound_user != env.from_:
            await link.send(_error_frame("BAD_USER", "Link bound to different user"))
            return

    error_code, pub = await _verify_user_envelope(env)
    if error_code:
        if not forwarded:
            await link.send(_error_frame("BAD_SIG", error_code))
        return

    content_err = _verify_user_message_content(env, pub)
    if content_err:
        await link.send(_error_frame("BAD_CONTENT_SIG", content_err))
        return

    if not forwarded and getattr(link, "kind", None) != "server":
        await _register_user_link(link, env, None)

    if not router.should_bypass_dedupe(payload_obj):
        target = env.to if env.to is not None else "__broadcast__"
        key = router.dedupe_key(env.ts, env.from_, str(target), payload_obj)
        if key in router.SEEN_IDS:
            return
        router.SEEN_IDS.add(key)

    if await _handle_file_flow(env, link):
        return

    if env.type in {"USER_LIST", "USER_LIST_MEMBERS", "LIST", "LIST_MEMBERS"}:
        response = _build_user_frame(
            "USER_LIST_RESPONSE",
            env.from_,
            {
                "server_id": LOCAL_SERVER_ID,
                "users": presence.list_online(),
            },
        )
        await link.send(response)
        return

    if env.type == "HEARTBEAT":
        ack = _build_user_frame("HEARTBEAT_ACK", env.from_, {"ts": _now_ms()})
        await link.send(ack)
        return

    if env.type in USER_DIRECT_TYPES and env.payload:
        log.info("MSG_DIRECT %s -> %s", env.from_, env.to)

    delivered = await _deliver_local(env)
    if delivered > 0:
        if not forwarded:
            ack = _build_user_frame("ACK", env.from_, {"delivered": delivered})
            await link.send(ack)
        return

    forwarded_ok = await _forward(env)
    if forwarded_ok:
        if not forwarded:
            ack = _build_user_frame("ACK", env.from_, {"forwarded": True})
            await link.send(ack)
        return

    if not forwarded:
        await link.send(_error_frame("NO_ROUTE", "Destination not local and no forwarder available"))


async def main() -> None:
    """Entrypoint that loads configuration and starts the websocket server."""
    global LOCAL_SERVER_ID, SHARED_SECRET, SSL_CONTEXT, LOCAL_URI

    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    _load_server_keys(cfg)

    LOCAL_SERVER_ID = cfg.get("server_id", LOCAL_SERVER_ID)
    SHARED_SECRET = cfg.get("shared_secret", DEFAULT_SHARED_SECRET)
    vulns = cfg.get("vulns", {})
    os.environ["VULN_WEAK_KEYS"] = "1" if vulns.get("weak_keys", False) else "0"
    os.environ["VULN_REPLAY"] = "1" if vulns.get("replay_bypass", False) else "0"

    host_str = cfg.get("listen", "127.0.0.1:8080")
    host, port_s = host_str.split(":")
    port = int(port_s)
    LOCAL_URI = f"ws://{host}:{port}"

    tls_cfg = cfg.get("tls")
    if isinstance(tls_cfg, dict) and tls_cfg.get("certfile") and tls_cfg.get("keyfile"):
        SSL_CONTEXT = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        SSL_CONTEXT.load_cert_chain(tls_cfg["certfile"], tls_cfg["keyfile"], password=tls_cfg.get("password"))

    await store.init(cfg.get("db_path", "socp.db"))
    await public.ensure_public_group()

    _update_local_server_id(LOCAL_SERVER_ID)

    bootstrap_entries = cfg.get("bootstrap_file")
    entries = []
    if bootstrap_entries:
        with open(bootstrap_entries, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        raw_servers: list[Dict[str, Any]] = []
        if isinstance(data, dict):
            raw_servers.extend(data.get("introducers", []))
            raw_servers.extend(data.get("servers", []))
        elif isinstance(data, list):
            raw_servers.extend(data)
        for entry in raw_servers:
            if not isinstance(entry, dict):
                continue
            item = dict(entry)
            if "uri" not in item:
                listen = item.get("listen")
                if listen:
                    item["uri"] = listen
                elif item.get("host") and item.get("port"):
                    item["uri"] = f"ws://{item['host']}:{item['port']}"
            entries.append(item)

    async def on_message(link, frame_text: str) -> None:
        try:
            obj = json.loads(frame_text)
        except json.JSONDecodeError as exc:
            await link.send(_error_frame("BAD_JSON", f"Invalid JSON: {exc.msg}"))
            return

        try:
            env = Envelope(**obj)
        except ValueError as exc:
            await link.send(_error_frame("BAD_ENVELOPE", "Envelope schema invalid", ref=str(exc)))
            return

        await _process_envelope(env, link)

    await peers.bootstrap(
        LOCAL_SERVER_ID,
        SHARED_SECRET,
        entries,
        on_message,
        _handle_peer_disconnect,
        presence.snapshot_local_users,
        _hello_builder,
    )

    heartbeat_task = asyncio.create_task(_heartbeat_loop())
    BACKGROUND_TASKS.append(heartbeat_task)

    log.info("Starting SOCP server on %s:%d", host, port)
    await ws.serve(
        host,
        port,
        on_message,
        on_disconnect_cb=_on_disconnect,
        ssl=SSL_CONTEXT,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(main())
