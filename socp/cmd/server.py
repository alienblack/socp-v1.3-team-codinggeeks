import argparse
import asyncio
import logging
import signal

from socp.core.config import ServerConfig
from socp.core.node import ServerRuntime

log = logging.getLogger("socp.server")


async def _run_server(config_path: str) -> None:
    cfg = ServerConfig.from_file(config_path)
    runtime = ServerRuntime(cfg)
    await runtime.start()

    stop_event = asyncio.Event()

    loop = asyncio.get_running_loop()
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop_event.set)
    except NotImplementedError:
        pass

    log.info("SOCP runtime started. Press Ctrl+C to stop.")
    await stop_event.wait()
    await runtime.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="SOCP v1.3 server")
    parser.add_argument("--config", required=True, help="Path to server YAML config")
    parser.add_argument("--once", action="store_true", help="Start and stop immediately (for tests)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if args.once:
        async def _once() -> None:
            cfg = ServerConfig.from_file(args.config)
            runtime = ServerRuntime(cfg)
            await runtime.start()
            await runtime.stop()
        asyncio.run(_once())
    else:
        asyncio.run(_run_server(args.config))


if __name__ == "__main__":
    main()
