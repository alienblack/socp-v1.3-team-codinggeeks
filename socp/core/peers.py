
import logging, asyncio
log = logging.getLogger("socp.peers")

async def bootstrap(bootstrap_list):
    # TODO: connect to introducers, validate, then link peers
    log.info("Bootstrap with introducers: %s", bootstrap_list)
    return {}
