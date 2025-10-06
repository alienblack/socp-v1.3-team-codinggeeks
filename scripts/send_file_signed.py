import argparse
import asyncio
import base64
import json
import os
import time
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def canonical_bytes(env: dict) -> bytes:
    body = {
        "type": env["type"],
        "from": env["from"],
        "to": env["to"],
        "ts": env["ts"],
        "payload": env["payload"],
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_envelope(priv, env: dict) -> dict:
    msg = canonical_bytes(env)
    sig = priv.sign(
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    env["sig"] = base64.b64encode(sig).decode("ascii")
    return env


def build_env(kind: str, sender: str, target, payload: dict) -> dict:
    return {
        "type": kind,
        "from": sender,
        "to": target,
        "ts": int(time.time()),
        "payload": payload,
        "sig": "",
    }


def serialise(env: dict) -> str:
    return json.dumps(env, separators=(",", ":"), ensure_ascii=False)


async def send_signed(ws, priv, env: dict, quiet: bool = False) -> str:
    signed = sign_envelope(priv, env)
    await ws.send(serialise(signed))
    reply = await ws.recv()
    if not quiet:
        print("<<", reply)
    return reply


async def run(args):
    with open(args.private_key, "rb") as fh:
        priv = serialization.load_pem_private_key(fh.read(), password=None)

    file_path = Path(args.file).resolve()
    if not file_path.is_file():
        raise SystemExit(f"File not found: {file_path}")

    file_bytes = file_path.read_bytes()
    digest = sha256(file_bytes).hexdigest()
    file_id = args.file_id or f"{args.user}-{uuid4().hex}"
    manifest = {
        "file_id": file_id,
        "name": file_path.name,
        "size": len(file_bytes),
        "sha256": digest,
    }

    async with websockets.connect(args.server) as ws:
        hello_payload = {"meta": {"display": args.display}}
        await send_signed(ws, priv, build_env("USER_HELLO", args.user, "server", hello_payload))

        start_env = build_env("FILE_START", args.user, args.recipient, {"manifest": manifest})
        await send_signed(ws, priv, start_env, quiet=args.quiet)

        chunk_size = args.chunk_size
        for index in range(0, len(file_bytes), chunk_size):
            chunk = file_bytes[index : index + chunk_size]
            payload = {
                "file_id": file_id,
                "chunk_index": index // chunk_size,
                "chunk": base64.b64encode(chunk).decode("ascii"),
                "manifest": manifest,
            }
            env = build_env("FILE_CHUNK", args.user, args.recipient, payload)
            await send_signed(ws, priv, env, quiet=args.quiet)

        finalize = build_env("FILE_END", args.user, args.recipient, manifest)
        await send_signed(ws, priv, finalize)
        print("File transfer complete. Manifest:", manifest)


def main():
    parser = argparse.ArgumentParser(description="Send a signed file transfer over SOCP")
    parser.add_argument("file", help="Path to the file to send")
    parser.add_argument("recipient", help="Recipient username")
    parser.add_argument("--server", default="ws://127.0.0.1:7001", help="WebSocket endpoint")
    parser.add_argument("--user", default="alice", help="Sender username")
    parser.add_argument("--private-key", default="alice_private.pem", help="PEM private key path")
    parser.add_argument("--display", default="Alice", help="Display name advertised in USER_HELLO")
    parser.add_argument("--file-id", default="", help="Override generated file identifier")
    parser.add_argument("--chunk-size", type=int, default=64 * 1024, help="Chunk size in bytes")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-chunk acknowledgements")
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
