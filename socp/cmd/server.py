
import argparse, asyncio, json, os, logging
from socp.core import ws, router, peers, presence, proto, store, public, files, crypto

log = logging.getLogger("socp.server")

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    # Load config (very simple YAML-like parsing for stub; replace with real yaml later)
    import yaml
    with open(args.config, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    host, port = cfg["listen"].split(":")
    port = int(port)

    await store.init(cfg.get("db_path", "socp.db"))
    await public.ensure_public_group()

    # Start WS server with a simple on_message callback
    async def on_message(link, frame_text):
        # TODO: parse envelope, route, verify, etc.
        log.info("Received frame: %s", frame_text[:200])

    log.info("Starting SOCP server on %s:%d", host, port)
    await ws.serve(host, port, on_message)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(main())
