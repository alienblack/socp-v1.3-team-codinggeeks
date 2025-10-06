import asyncio
import contextlib
import hashlib
import logging
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import click
import orjson
import websockets

from socp.core import crypto, proto

log = logging.getLogger("socp.client")


@dataclass(slots=True)
class ClientKeys:
    signing: crypto.RSAKeyPair
    encryption: crypto.RSAKeyPair


@dataclass
class InboundFile:
    sender: str
    name: str
    size: int
    sha256: str
    mode: str
    buffer: bytearray = field(default_factory=bytearray)

    def add_chunk(self, data: bytes) -> None:
        self.buffer.extend(data)

    def verify(self) -> bool:
        digest = hashlib.sha256(self.buffer).hexdigest()
        return digest == self.sha256 and len(self.buffer) == self.size


def ensure_client_keys(base_dir: Path) -> ClientKeys:
    base_dir.mkdir(parents=True, exist_ok=True)
    sign_pair = crypto.ensure_rsa_pair(base_dir / "sign_priv.pem", base_dir / "sign_pub.pem")
    enc_pair = crypto.ensure_rsa_pair(base_dir / "enc_priv.pem", base_dir / "enc_pub.pem")
    return ClientKeys(signing=sign_pair, encryption=enc_pair)


class ClientApp:
    def __init__(self, server_url: str, user_id: str, key_dir: Path):
        self.server_url = server_url
        self.user_id = user_id
        self.key_dir = key_dir
        self.keys = ensure_client_keys(key_dir)
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.server_id: Optional[str] = None
        self.directory: Dict[str, Dict[str, Any]] = {}
        self.public_channel_key: Optional[bytes] = None
        self.public_wraps: Dict[str, str] = {}
        self.file_downloads: Dict[str, InboundFile] = {}
        self.receiver_task: Optional[asyncio.Task] = None
        self.stop_event = asyncio.Event()

    async def run(self) -> None:
        async with websockets.connect(self.server_url) as ws:
            self.ws = ws
            await self._send_user_hello()
            self.receiver_task = asyncio.create_task(self._receiver_loop())
            try:
                await self._repl_loop()
            finally:
                self.stop_event.set()
                if self.receiver_task:
                    self.receiver_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await self.receiver_task

    async def _send_user_hello(self) -> None:
        payload = {
            "client": self.user_id,
            "pubkey": crypto.b64url(self.keys.signing.public_pem),
            "enc_pubkey": crypto.b64url(self.keys.encryption.public_pem),
            "meta": {"display_name": self.user_id},
        }
        await self._send_envelope("USER_HELLO", payload, sign=False)

    async def _send_envelope(self, type_: str, payload: Dict[str, Any], *, to: Optional[str] = None, sign: bool = True) -> None:
        assert self.ws is not None, "connection not established"
        target = to or self.server_id or "*"
        envelope = proto.build_envelope(type_, self.user_id, target, payload)
        if sign:
            envelope = proto.sign_envelope(envelope, self.keys.signing.private_pem)
        data = proto.envelope_to_dict(envelope)
        await self.ws.send(orjson.dumps(data).decode("utf-8"))

    async def _receiver_loop(self) -> None:
        assert self.ws is not None
        try:
            async for raw in self.ws:
                data = orjson.loads(raw)
                envelope = proto.Envelope(**data)
                if not self.server_id:
                    self.server_id = envelope.from_
                await self._handle_incoming(envelope)
        except websockets.ConnectionClosed:
            log.info("Server closed connection")
            self.stop_event.set()

    async def _handle_incoming(self, envelope: proto.Envelope) -> None:
        typ = envelope.type
        if typ == "ACK":
            await self._handle_ack(envelope)
        elif typ == "ERROR":
            self._handle_error(envelope)
        elif typ == "LIST_USERS_RESULT":
            self._handle_list_result(envelope.payload)
        elif typ == "USER_DELIVER":
            self._handle_dm_delivery(envelope.payload)
        elif typ == "PUBLIC_DELIVER":
            self._handle_public_delivery(envelope.payload)
        elif typ in {"FILE_START", "FILE_CHUNK", "FILE_END"}:
            await self._handle_file_delivery(typ, envelope.payload)
        elif typ in {"PUBLIC_CHANNEL_ADD", "PUBLIC_CHANNEL_UPDATED"}:
            self._handle_public_update(envelope.payload)
        elif typ == "PUBLIC_CHANNEL_KEY_SHARE":
            self._handle_public_share(envelope.payload)
        else:
            log.debug("Unhandled frame %s", typ)

    async def _handle_ack(self, envelope: proto.Envelope) -> None:
        ref = envelope.payload.get("msg_ref")
        if ref == "USER_HELLO" and self.server_id:
            await self._send_envelope("LIST_USERS", {})
        log.info("ACK: %s", envelope.payload)

    def _handle_error(self, envelope: proto.Envelope) -> None:
        log.error("Server error: %s", envelope.payload)

    def _handle_list_result(self, payload: Dict[str, Any]) -> None:
        users = payload.get("users", [])
        for entry in users:
            uid = entry.get("user_id")
            if not uid:
                continue
            self.directory[uid] = entry
        names = ", ".join(sorted(entry["user_id"] for entry in users if entry.get("user_id")))
        print(f"Online users: {names}")

    def _handle_dm_delivery(self, payload: Dict[str, Any]) -> None:
        sender = payload.get("from")
        ciphertext_b64 = payload.get("ciphertext")
        sender_pub_b64 = payload.get("sender_pub")
        content_sig = payload.get("content_sig")
        ts = payload.get("ts")
        if not sender or not ciphertext_b64 or not sender_pub_b64 or not content_sig or ts is None:
            log.warning("Malformed USER_DELIVER payload")
            return
        try:
            ciphertext = crypto.b64url_decode(ciphertext_b64)
            sender_pub = crypto.b64url_decode(sender_pub_b64)
        except ValueError:
            log.warning("Invalid base64 in DM payload")
            return
        digest = crypto.content_digest_direct(ciphertext, sender, self.user_id, ts)
        if not crypto.verify_content_signature(sender_pub, digest, content_sig):
            log.warning("Content signature failed for message from %s", sender)
            return
        try:
            plaintext = crypto.rsa_decrypt_oaep(self.keys.encryption.private_pem, ciphertext)
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("Failed to decrypt message: %s", exc)
            return
        text = plaintext.decode("utf-8", errors="replace")
        print(f"[{sender}] {text}")

    def _handle_public_delivery(self, payload: Dict[str, Any]) -> None:
        if not self.public_channel_key:
            log.debug("No public channel key yet; dropping message")
            return
        sender = payload.get("from")
        ciphertext_b64 = payload.get("ciphertext")
        sender_pub_b64 = payload.get("sender_pub")
        content_sig = payload.get("content_sig")
        ts = payload.get("ts")
        if not sender or not ciphertext_b64 or not sender_pub_b64 or not content_sig or ts is None:
            return
        try:
            ciphertext = crypto.b64url_decode(ciphertext_b64)
            sender_pub = crypto.b64url_decode(sender_pub_b64)
        except ValueError:
            return
        digest = crypto.content_digest_public(ciphertext, sender, ts)
        if not crypto.verify_content_signature(sender_pub, digest, content_sig):
            log.warning("Public message signature invalid from %s", sender)
            return
        try:
            plaintext = crypto.aes_gcm_decrypt(self.public_channel_key, ciphertext)
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("Failed to decrypt public message: %s", exc)
            return
        text = plaintext.decode("utf-8", errors="replace")
        print(f"[all:{sender}] {text}")

    async def _handle_file_delivery(self, frame_type: str, payload: Dict[str, Any]) -> None:
        user_from = payload.get("from") or payload.get("sender")
        file_id = payload.get("file_id")
        if not user_from or not file_id:
            return
        if frame_type == "FILE_START":
            manifest = InboundFile(
                sender=user_from,
                name=payload.get("name", f"{file_id}.bin"),
                size=int(payload.get("size", 0)),
                sha256=payload.get("sha256", ""),
                mode=payload.get("mode", "dm"),
            )
            self.file_downloads[file_id] = manifest
            print(f"[file] {user_from} started sending {manifest.name} ({manifest.size} bytes)")
            return
        if file_id not in self.file_downloads:
            log.warning("Unknown file transfer %s", file_id)
            return
        transfer = self.file_downloads[file_id]
        if frame_type == "FILE_CHUNK":
            ciphertext_b64 = payload.get("ciphertext")
            sender_pub_b64 = payload.get("sender_pub")
            content_sig = payload.get("content_sig")
            ts = payload.get("ts")
            if not ciphertext_b64 or not sender_pub_b64 or not content_sig or ts is None:
                return
            try:
                ciphertext = crypto.b64url_decode(ciphertext_b64)
                sender_pub = crypto.b64url_decode(sender_pub_b64)
            except ValueError:
                return
            digest = crypto.content_digest_direct(ciphertext, user_from, self.user_id, ts)
            if not crypto.verify_content_signature(sender_pub, digest, content_sig):
                log.warning("Invalid chunk signature for %s", file_id)
                return
            plaintext = crypto.rsa_decrypt_oaep(self.keys.encryption.private_pem, ciphertext)
            transfer.add_chunk(plaintext)
        elif frame_type == "FILE_END":
            ciphertext_b64 = payload.get("ciphertext")
            content_sig = payload.get("content_sig")
            ts = payload.get("ts")
            if ciphertext_b64 and content_sig and ts is not None:
                try:
                    ciphertext = crypto.b64url_decode(ciphertext_b64)
                except ValueError:
                    ciphertext = None
                else:
                    digest = crypto.content_digest_direct(ciphertext, user_from, self.user_id, ts)
                    sender_pub_b64 = payload.get("sender_pub")
                    if sender_pub_b64:
                        sender_pub = crypto.b64url_decode(sender_pub_b64)
                        if not crypto.verify_content_signature(sender_pub, digest, content_sig):
                            log.warning("Invalid FILE_END signature for %s", file_id)
                            return
            if transfer.verify():
                download_dir = self.key_dir / "downloads"
                download_dir.mkdir(parents=True, exist_ok=True)
                dest = download_dir / transfer.name
                dest.write_bytes(transfer.buffer)
                print(f"[file] received {transfer.name} -> {dest}")
            else:
                log.warning("File verification failed for %s", file_id)
            self.file_downloads.pop(file_id, None)

    def _handle_public_update(self, payload: Dict[str, Any]) -> None:
        wraps = []
        if payload.get("member_id") == self.user_id and payload.get("wrapped_key"):
            wraps.append({"member_id": payload.get("member_id"), "wrapped_key": payload.get("wrapped_key")})
        wraps.extend(payload.get("wraps", []))
        for wrap in wraps:
            if wrap.get("member_id") != self.user_id:
                continue
            wrapped_b64 = wrap.get("wrapped_key")
            if not wrapped_b64:
                continue
            try:
                wrapped = crypto.b64url_decode(wrapped_b64)
                key = crypto.rsa_decrypt_oaep(self.keys.encryption.private_pem, wrapped)
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("Failed to unwrap public channel key: %s", exc)
                continue
            self.public_channel_key = key
            print("[public] channel key updated")

    def _handle_public_share(self, payload: Dict[str, Any]) -> None:
        wraps = payload.get("shares", [])
        for wrap in wraps:
            if wrap.get("member_id") == self.user_id:
                self._handle_public_update({"wraps": [wrap]})

    async def _repl_loop(self) -> None:
        loop = asyncio.get_running_loop()
        print("SOCP client ready. Commands: /list, /tell <user> <text>, /all <text>, /file <user> <path>, /quit")
        while not self.stop_event.is_set():
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            if line.startswith("/"):
                await self._handle_command(line)
            else:
                await self._cmd_all(line)

    async def _handle_command(self, line: str) -> None:
        parts = line.split()
        cmd = parts[0]
        if cmd == "/list":
            await self._send_envelope("LIST_USERS", {})
        elif cmd == "/tell" and len(parts) >= 3:
            target = parts[1]
            text = line.split(" ", 2)[2]
            await self._cmd_tell(target, text)
        elif cmd == "/all" and len(parts) >= 2:
            text = line.split(" ", 1)[1]
            await self._cmd_all(text)
        elif cmd == "/file" and len(parts) >= 3:
            target = parts[1]
            path = line.split(" ", 2)[2]
            await self._cmd_file(target, Path(path).expanduser())
        elif cmd == "/quit":
            self.stop_event.set()
        else:
            print("Unknown command")

    def _lookup_directory(self, user_id: str) -> Optional[Dict[str, Any]]:
        entry = self.directory.get(user_id)
        if entry:
            return entry
        print("User not in directory. Run /list first.")
        return None

    async def _cmd_tell(self, target: str, text: str) -> None:
        entry = self._lookup_directory(target)
        if not entry:
            return
        try:
            enc_key = crypto.b64url_decode(entry["enc_pubkey"])
        except Exception:
            print("Missing encryption key for user")
            return
        ciphertext = crypto.rsa_encrypt_oaep(enc_key, text.encode("utf-8"))
        ciphertext_b64 = crypto.b64url(ciphertext)
        ts = proto.now_ms()
        digest = crypto.content_digest_direct(ciphertext, self.user_id, target, ts)
        content_sig = crypto.sign_content(self.keys.signing.private_pem, digest)
        payload = {
            "to": target,
            "ciphertext": ciphertext_b64,
            "sender_pub": crypto.b64url(self.keys.signing.public_pem),
            "content_sig": content_sig,
            "ts": ts,
            "hops": 0,
        }
        await self._send_envelope("MSG_DIRECT", payload)

    async def _cmd_all(self, text: str) -> None:
        if not self.public_channel_key:
            print("Public channel key not available yet")
            return
        ciphertext = crypto.aes_gcm_encrypt(self.public_channel_key, text.encode("utf-8"))
        ciphertext_b64 = crypto.b64url(ciphertext)
        ts = proto.now_ms()
        digest = crypto.content_digest_public(ciphertext, self.user_id, ts)
        content_sig = crypto.sign_content(self.keys.signing.private_pem, digest)
        payload = {
            "group_id": "public",
            "ciphertext": ciphertext_b64,
            "sender_pub": crypto.b64url(self.keys.signing.public_pem),
            "content_sig": content_sig,
            "ts": ts,
            "sender": self.user_id,
        }
        await self._send_envelope("MSG_PUBLIC_CHANNEL", payload)

    async def _cmd_file(self, target: str, path: Path) -> None:
        if not path.exists():
            print(f"File not found: {path}")
            return
        entry = self._lookup_directory(target)
        if not entry:
            return
        try:
            enc_key = crypto.b64url_decode(entry["enc_pubkey"])
        except Exception:
            print("Missing encryption key for user")
            return
        data = path.read_bytes()
        file_id = str(uuid.uuid4())
        sha256 = hashlib.sha256(data).hexdigest()
        await self._send_envelope(
            "FILE_START",
            {
                "to": target,
                "file_id": file_id,
                "name": path.name,
                "size": len(data),
                "sha256": sha256,
                "mode": "dm",
            },
        )
        chunk_size = 190
        for index, offset in enumerate(range(0, len(data), chunk_size)):
            chunk = data[offset : offset + chunk_size]
            ciphertext = crypto.rsa_encrypt_oaep(enc_key, chunk)
            ciphertext_b64 = crypto.b64url(ciphertext)
            ts = proto.now_ms()
            digest = crypto.content_digest_direct(ciphertext, self.user_id, target, ts)
            content_sig = crypto.sign_content(self.keys.signing.private_pem, digest)
            payload = {
                "to": target,
                "file_id": file_id,
                "index": index,
                "ciphertext": ciphertext_b64,
                "sender_pub": crypto.b64url(self.keys.signing.public_pem),
                "content_sig": content_sig,
                "ts": ts,
            }
            await self._send_envelope("FILE_CHUNK", payload)
        final_blob = sha256.encode("ascii")
        final_ciphertext = crypto.rsa_encrypt_oaep(enc_key, final_blob[:190])
        final_ciphertext_b64 = crypto.b64url(final_ciphertext)
        ts = proto.now_ms()
        digest = crypto.content_digest_direct(final_ciphertext, self.user_id, target, ts)
        content_sig = crypto.sign_content(self.keys.signing.private_pem, digest)
        await self._send_envelope(
            "FILE_END",
            {
                "to": target,
                "file_id": file_id,
                "ciphertext": final_ciphertext_b64,
                "sender_pub": crypto.b64url(self.keys.signing.public_pem),
                "content_sig": content_sig,
                "ts": ts,
            },
        )
        print(f"[file] sent {path} to {target}")


@click.group()
@click.option("--server", required=True, help="ws://host:port")
@click.option("--user", "user_id", required=True, help="User identifier (UUID)")
@click.option("--keys-dir", default="~/.socp", type=click.Path(), help="Directory for client keys")
@click.pass_context
def cli(ctx: click.Context, server: str, user_id: str, keys_dir: str) -> None:
    ctx.ensure_object(dict)
    ctx.obj["server"] = server
    ctx.obj["user"] = user_id
    ctx.obj["keys_dir"] = Path(keys_dir).expanduser() / user_id


@cli.command()
@click.pass_context
def repl(ctx: click.Context) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app = ClientApp(ctx.obj["server"], ctx.obj["user"], ctx.obj["keys_dir"])
    asyncio.run(app.run())


if __name__ == "__main__":
    cli()
