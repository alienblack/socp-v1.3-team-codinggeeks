import argparse
import asyncio
import base64
import json
import time

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
        "ts": int(time.time() * 1000),
        "payload": payload,
        "sig": "",
    }


def serialise(env: dict) -> str:
    return json.dumps(env, separators=(",", ":"), ensure_ascii=False)


async def run(args):
    with open(args.private_key, "rb") as fh:
        priv = serialization.load_pem_private_key(fh.read(), password=None)

    async with websockets.connect(args.server) as ws:
        pub_pem = (
            priv.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )
        hello_payload = {
            "client": "send_signed_alice",
            "pubkey": pub_pem,
            "meta": {"display": args.display},
        }
        hello = sign_envelope(priv, build_env("USER_HELLO", args.user, "server", hello_payload))
        await ws.send(serialise(hello))
        print("<<", await ws.recv())

        content_bytes = args.message.encode("utf-8")
        content_sig = priv.sign(
            content_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        message_payload = {
            "content": base64.b64encode(content_bytes).decode("ascii"),
            "content_sig": base64.b64encode(content_sig).decode("ascii"),
            "encoding": "utf-8",
        }
        message_env = sign_envelope(priv, build_env("MSG_DIRECT", args.user, args.recipient, message_payload))
        await ws.send(serialise(message_env))
        print("<<", await ws.recv())

        if args.list_after:
            list_env = sign_envelope(priv, build_env("USER_LIST", args.user, "server", {}))
            await ws.send(serialise(list_env))
            print("<<", await ws.recv())


def main():
    parser = argparse.ArgumentParser(description="Send a signed SOCP envelope from a local key")
    parser.add_argument("message", help="Message text to send")
    parser.add_argument("recipient", help="Recipient username")
    parser.add_argument("--server", default="ws://127.0.0.1:7001", help="WebSocket endpoint")
    parser.add_argument("--user", default="alice", help="Sender username")
    parser.add_argument("--private-key", default="alice_private.pem", help="PEM private key path")
    parser.add_argument("--display", default="Alice", help="Display name advertised in USER_HELLO")
    parser.add_argument("--list-after", action="store_true", help="Request member list after sending the message")
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
