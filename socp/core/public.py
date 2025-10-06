
import logging, time
from . import store
log = logging.getLogger("socp.public")

async def ensure_public_group():
    await store.ensure_public_group()

async def add_member(user_id: str):
    # TODO: generate new group version, wrap key for member, persist
    log.info("Add member to public: %s", user_id)
