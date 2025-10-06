import argparse
import asyncio
from pathlib import Path

from socp.core import store


async def run(args):
    await store.init(args.db)
    pubkey = Path(args.pubkey).read_bytes()
    meta = {}
    if args.display:
        meta["display"] = args.display
    await store.upsert_user(
        args.user,
        pubkey,
        privkey_store=args.priv_store or "",
        pake_password=args.pake or "",
        meta=meta,
    )
    await store.close()


def main():
    parser = argparse.ArgumentParser(description="Register or update a user in the SOCP SQLite store")
    parser.add_argument("user", help="Username")
    parser.add_argument("pubkey", help="Path to PEM public key")
    parser.add_argument("--db", default="socp.db", help="SQLite database path")
    parser.add_argument("--priv-store", default="", help="Opaque private key storage blob")
    parser.add_argument("--pake", default="", help="PAKE password verifier")
    parser.add_argument("--display", default="", help="Display name metadata")
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
