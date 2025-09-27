
import aiosqlite, asyncio, os, time, json

DB = None

async def init(path: str = "socp.db"):
    global DB
    DB = await aiosqlite.connect(path)
    with open("db/schema.sql","r",encoding="utf-8") as f:
        await DB.executescript(f.read())
    await DB.commit()

async def ensure_public_group():
    cur = await DB.execute("SELECT 1 FROM groups WHERE group_id='public'")
    row = await cur.fetchone()
    if not row:
        await DB.execute("INSERT INTO groups(group_id,creator_id,created_at,meta,version) VALUES(?,?,?,?,?)",
                         ("public","system",int(time.time()), json.dumps({"title":"Public"}), 1))
        await DB.commit()
