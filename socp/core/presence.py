
import logging
log = logging.getLogger("socp.presence")

async def on_user_local_join(user_id: str, meta: dict):
    # TODO: broadcast USER_ADVERTISE
    log.info("Advertise user join: %s", user_id)

async def on_user_local_leave(user_id: str):
    # TODO: broadcast USER_REMOVE
    log.info("Advertise user leave: %s", user_id)
