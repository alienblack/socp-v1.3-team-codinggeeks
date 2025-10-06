
import argparse, asyncio, json, os, logging
from socp.core import ws, router, peers, presence, proto, store, public, files, crypto

log = logging.getLogger("socp.server")

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    import yaml
    with open(args.config, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    host, port = cfg["listen"].split(":")
    port = int(port)

    await store.init(cfg.get("db_path", "socp.db"))
    await public.ensure_public_group()

    reassembler = files.FileReassembler(out_dir="received")

    async def on_message(link, frame_text):
        try:
            frame = json.loads(frame_text)
        except Exception:
            log.warning("Received non-JSON frame (ignored): %s", frame_text[:200])
            return

        try:
            res = files.handle_event(frame, reassembler)
        except Exception as e:
            log.exception("Error while handling file frame: %s", e)
            res = None

        if isinstance(res, tuple) and frame.get("type") == "FILE_END":
            path, ok = res
            log.info("Saved incoming file: %s verified=%s", path, ok)
            return

        log.info("Received frame: %s", frame_text[:200])

    log.info("Starting SOCP server on %s:%d", host, port)
    await ws.serve(host, port, on_message)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(main())
