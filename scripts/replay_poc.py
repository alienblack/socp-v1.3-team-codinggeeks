
#!/usr/bin/env python3
import argparse, json, asyncio, websockets, sys

async def replay(uri, replay_file):
    async with websockets.connect(uri) as ws:
        with open(replay_file, "r", encoding="utf-8") as f:
            data = f.read()
        await ws.send(data)
        print("Replayed frame from", replay_file)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--to", required=True, help="ws://host:port")
    ap.add_argument("--replay", required=True, help="file with captured JSON frame")
    args = ap.parse_args()
    asyncio.run(replay(args.to, args.replay))
