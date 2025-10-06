
import argparse
import asyncio
import logging

from socp.core import crypto, files, peers, presence, proto, public, router, store, ws

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
    router_state = router.Router(cfg["server_id"])

    log.info("Starting SOCP server on %s:%d", host, port)
    await ws.serve(host, port, router_state)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(main())
