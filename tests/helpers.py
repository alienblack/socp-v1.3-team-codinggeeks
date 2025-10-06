import asyncio
import contextlib
import hashlib
import socket
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import orjson
import websockets

from socp.core import crypto
from socp.core.config import IntroducerConfig, ServerConfig, VulnerabilityToggles
from socp.core.node import ServerRuntime
from socp.core import proto


def unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class TestServer:
    runtime: ServerRuntime
    host: str
    port: int

    @classmethod
    def create(cls, tmp_path: Path, server_id: Optional[str] = None, *, port: Optional[int] = None) -> "TestServer":
        srv_id = server_id or str(uuid.uuid4())
        listen_port = port or unused_tcp_port()
        key_dir = tmp_path / srv_id
        cfg = ServerConfig(
            server_id=srv_id,
            listen_host="127.0.0.1",
            listen_port=listen_port,
            db_path=tmp_path / f"{srv_id}.db",
            private_key_path=key_dir / "priv.pem",
            public_key_path=key_dir / "pub.pem",
            bootstrap_file=tmp_path / "bootstrap.yaml",
            introducers=[],
            heartbeat_secs=1,
            dead_after_secs=3,
            vulnerabilities=VulnerabilityToggles(weak_keys=True, replay_bypass=True),
        )
        runtime = ServerRuntime(cfg)
        return cls(runtime=runtime, host="127.0.0.1", port=listen_port)

    async def start(self) -> None:
        await self.runtime.start()

    async def stop(self) -> None:
        await self.runtime.stop()

    async def connect_to(self, other: "TestServer") -> None:
        await self.runtime._dial_server(other.host, other.port)
        await asyncio.sleep(0.2)


class TestClient:
    def __init__(self, user_id: Optional[str] = None):
        self.user_id = user_id or str(uuid.uuid4())
        self.sign_pair = crypto.generate_rsa_keypair()
        self.enc_pair = crypto.generate_rsa_keypair()
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.server_id: Optional[str] = None
        self.directory: Dict[str, Dict[str, Any]] = {}
        self.public_channel_key: Optional[bytes] = None
        self.queue: asyncio.Queue = asyncio.Queue()
        self.receiver_task: Optional[asyncio.Task] = None
        self.handshake_complete = asyncio.Event()

    async def connect(self, server: TestServer) -> None:
        self.ws = await websockets.connect(f"ws://{server.host}:{server.port}")
        payload = {
            "client": self.user_id,
            "pubkey": crypto.b64url(self.sign_pair.public_pem),
            "enc_pubkey": crypto.b64url(self.enc_pair.public_pem),
            "meta": {"display_name": self.user_id},
        }
        await self._send("USER_HELLO", payload, sign=False)
        self.receiver_task = asyncio.create_task(self._receiver_loop())
        await self.handshake_complete.wait()

    async def close(self) -> None:
        if self.receiver_task:
            self.receiver_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.receiver_task
        if self.ws:
            await self.ws.close()

    async def _receiver_loop(self) -> None:
        assert self.ws is not None
        try:
            async for raw in self.ws:
                env = proto.Envelope(**orjson.loads(raw))
                if env.type == "ACK":
                    if env.payload.get("msg_ref") == "USER_HELLO":
                        self.server_id = env.from_
                        self.handshake_complete.set()
                        await self._send("LIST_USERS", {})
                    continue
                if env.type == "LIST_USERS_RESULT":
                    for entry in env.payload.get("users", []):
                        uid = entry.get("user_id")
                        if uid:
                            self.directory[uid] = entry
                    continue
                if env.type in {"PUBLIC_CHANNEL_ADD", "PUBLIC_CHANNEL_UPDATED"}:
                    self._handle_public_update(env.payload)
                    continue
                if env.type == "PUBLIC_CHANNEL_KEY_SHARE":
                    for wrap in env.payload.get("shares", []):
                        self._handle_public_update({"wraps": [wrap]})
                    continue
                await self.queue.put(env)
        except websockets.ConnectionClosed:
            pass

    def _handle_public_update(self, payload: Dict[str, Any]) -> None:
        wraps = []
        if payload.get("member_id") == self.user_id and payload.get("wrapped_key"):
            wraps.append({"member_id": payload["member_id"], "wrapped_key": payload["wrapped_key"]})
        wraps.extend(payload.get("wraps", []))
        for wrap in wraps:
            if wrap.get("member_id") != self.user_id:
                continue
            wrapped_b64 = wrap.get("wrapped_key")
            if not wrapped_b64:
                continue
            wrapped = crypto.b64url_decode(wrapped_b64)
            try:
                key = crypto.rsa_decrypt_oaep(self.enc_pair.private_pem, wrapped)
            except Exception:
                continue
            self.public_channel_key = key

    async def _send(self, type_: str, payload: Dict[str, Any], *, sign: bool = True, ts: Optional[int] = None) -> None:
        assert self.ws is not None
        target = self.server_id or "*"
        envelope = proto.build_envelope(type_, self.user_id, target, payload, ts=ts)
        await self._send_envelope(envelope, sign=sign)

    async def _send_envelope(self, envelope: proto.Envelope, *, sign: bool = True) -> None:
        assert self.ws is not None
        if sign:
            envelope = proto.sign_envelope(envelope, self.sign_pair.private_pem)
        await self.ws.send(orjson.dumps(proto.envelope_to_dict(envelope)).decode("utf-8"))

    async def send_direct(self, target: str, text: str) -> None:
        enc_entry = self.directory.get(target)
        if not enc_entry:
            await self._send("LIST_USERS", {})
            await asyncio.sleep(0.1)
            enc_entry = self.directory.get(target)
        enc_key = crypto.b64url_decode(enc_entry["enc_pubkey"])
        ciphertext = crypto.rsa_encrypt_oaep(enc_key, text.encode("utf-8"))
        ts = proto.now_ms()
        digest = crypto.content_digest_direct(ciphertext, self.user_id, target, ts)
        payload = {
            "to": target,
            "ciphertext": crypto.b64url(ciphertext),
            "sender_pub": crypto.b64url(self.sign_pair.public_pem),
            "content_sig": crypto.sign_content(self.sign_pair.private_pem, digest),
            "ts": ts,
            "hops": 0,
        }
        await self._send("MSG_DIRECT", payload)

    async def recv_direct(self, timeout: float = 1.0) -> str:
        env = await asyncio.wait_for(self.queue.get(), timeout)
        assert env.type == "USER_DELIVER"
        sender = env.payload.get("from")
        ciphertext = crypto.b64url_decode(env.payload["ciphertext"])
        digest = crypto.content_digest_direct(ciphertext, sender, self.user_id, env.payload["ts"])
        sender_pub = crypto.b64url_decode(env.payload["sender_pub"])
        assert crypto.verify_content_signature(sender_pub, digest, env.payload["content_sig"])
        plaintext = crypto.rsa_decrypt_oaep(self.enc_pair.private_pem, ciphertext)
        return plaintext.decode("utf-8")

    async def send_direct_duplicate(self, target: str, text: str) -> None:
        ts = proto.now_ms()
        envelope = self.build_direct_envelope(target, text, ts)
        await self._send_envelope(envelope)
        await self._send_envelope(envelope)

    async def send_public(self, text: str) -> None:
        if not self.public_channel_key:
            raise RuntimeError("public channel key unavailable")
        ciphertext = crypto.aes_gcm_encrypt(self.public_channel_key, text.encode("utf-8"))
        ts = proto.now_ms()
        digest = crypto.content_digest_public(ciphertext, self.user_id, ts)
        payload = {
            "group_id": "public",
            "ciphertext": crypto.b64url(ciphertext),
            "sender_pub": crypto.b64url(self.sign_pair.public_pem),
            "content_sig": crypto.sign_content(self.sign_pair.private_pem, digest),
            "ts": ts,
            "sender": self.user_id,
        }
        await self._send("MSG_PUBLIC_CHANNEL", payload)

    async def refresh_directory(self) -> None:
        await self._send("LIST_USERS", {})
        await asyncio.sleep(0.1)

    async def recv_public(self, timeout: float = 1.0) -> str:
        env = await asyncio.wait_for(self.queue.get(), timeout)
        assert env.type == "PUBLIC_DELIVER"
        ciphertext = crypto.b64url_decode(env.payload["ciphertext"])
        plaintext = crypto.aes_gcm_decrypt(self.public_channel_key, ciphertext)
        return plaintext.decode("utf-8")

    async def send_file(self, target: str, data: bytes, *, name: str = "test.bin") -> str:
        file_id = str(uuid.uuid4())
        sha256 = hashlib.sha256(data).hexdigest()
        enc_key = crypto.b64url_decode(self.directory[target]["enc_pubkey"])
        await self._send(
            "FILE_START",
            {
                "to": target,
                "file_id": file_id,
                "name": name,
                "size": len(data),
                "sha256": sha256,
                "mode": "dm",
            },
        )
        chunk_size = 190
        for index, offset in enumerate(range(0, len(data), chunk_size)):
            chunk = data[offset : offset + chunk_size]
            ciphertext = crypto.rsa_encrypt_oaep(enc_key, chunk)
            ts = proto.now_ms()
            digest = crypto.content_digest_direct(ciphertext, self.user_id, target, ts)
            await self._send(
                "FILE_CHUNK",
                {
                    "to": target,
                    "file_id": file_id,
                    "index": index,
                    "ciphertext": crypto.b64url(ciphertext),
                    "sender_pub": crypto.b64url(self.sign_pair.public_pem),
                    "content_sig": crypto.sign_content(self.sign_pair.private_pem, digest),
                    "ts": ts,
                },
            )
        final_blob = hashlib.sha256(data).digest()
        ciphertext = crypto.rsa_encrypt_oaep(enc_key, final_blob[:190])
        ts = proto.now_ms()
        digest = crypto.content_digest_direct(ciphertext, self.user_id, target, ts)
        await self._send(
            "FILE_END",
            {
                "to": target,
                "file_id": file_id,
                "ciphertext": crypto.b64url(ciphertext),
                "sender_pub": crypto.b64url(self.sign_pair.public_pem),
                "content_sig": crypto.sign_content(self.sign_pair.private_pem, digest),
                "ts": ts,
            },
        )
        return file_id

    async def recv_file(self, timeout: float = 1.0) -> bytes:
        chunks: Dict[int, bytes] = {}
        while True:
            env = await asyncio.wait_for(self.queue.get(), timeout)
            if env.type == "FILE_CHUNK":
                ciphertext = crypto.b64url_decode(env.payload["ciphertext"])
                plaintext = crypto.rsa_decrypt_oaep(self.enc_pair.private_pem, ciphertext)
                chunks[env.payload["index"]] = plaintext
            elif env.type == "FILE_END":
                ordered = b"".join(chunks[i] for i in sorted(chunks))
                return ordered




