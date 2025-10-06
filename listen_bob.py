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
        "ts": int(time.time()),
        "payload": payload,
        "sig": "",
    }


def serialise(env: dict) -> str:
    return json.dumps(env, separators=(",", ":"), ensure_ascii=False)


async def run(args):
    with open(args.private_key, "rb") as fh:
        priv = serialization.load_pem_private_key(fh.read(), password=None)

    async with websockets.connect(args.server) as ws:
        hello_payload = {"meta": {"display": args.display}}
        hello = sign_envelope(priv, build_env("USER_HELLO", args.user, "server", hello_payload))
        await ws.send(serialise(hello))
        print(">>", "USER_HELLO")
        print("<<", await ws.recv())

        if args.list_once:
            request = sign_envelope(priv, build_env("USER_LIST", args.user, "server", {}))
            await ws.send(serialise(request))
            print(">>", "USER_LIST")

        print("Listening for incoming frames as", args.user)
        while True:
            msg = await ws.recv()
            print("<<", msg)


def main():
    parser = argparse.ArgumentParser(description="Listen for signed SOCP messages")
    parser.add_argument("--server", default="ws://127.0.0.1:7001", help="WebSocket endpoint")
    parser.add_argument("--user", default="bob", help="Local username")
    parser.add_argument("--private-key", default="bob_private.pem", help="PEM private key path")
    parser.add_argument("--display", default="Bob", help="Display name advertised in USER_HELLO")
    parser.add_argument("--list-once", action="store_true", help="Request a member list after USER_HELLO")
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
