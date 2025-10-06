import json
import time
from typing import Dict, Optional

import aiosqlite

DB: Optional[aiosqlite.Connection] = None


async def init(path: str = "socp.db") -> None:
    global DB
    if DB is not None:
        return
    DB = await aiosqlite.connect(path)
    await DB.execute("PRAGMA foreign_keys = ON")
    with open("db/schema.sql", "r", encoding="utf-8") as f:
        await DB.executescript(f.read())
    await DB.commit()


async def close() -> None:
    global DB
    if DB is not None:
        await DB.close()
        DB = None


async def ensure_public_group() -> None:
    assert DB is not None, "store not initialised"
    cur = await DB.execute("SELECT 1 FROM groups WHERE group_id='public'")
    row = await cur.fetchone()
    if not row:
        await DB.execute(
            "INSERT INTO groups(group_id,creator_id,created_at,meta,version) VALUES(?,?,?,?,?)",
            ("public", "system", int(time.time()), json.dumps({"title": "Public"}), 1),
        )
        await DB.commit()


async def upsert_user(user_id: str, pubkey: bytes, meta: Dict[str, object]) -> None:
    assert DB is not None, "store not initialised"
    meta_json = json.dumps(meta or {})
    await DB.execute(
        """
        INSERT INTO users(user_id, pubkey, privkey_store, pake_password, meta, version)
        VALUES(?, ?, ?, ?, ?, 1)
        ON CONFLICT(user_id) DO UPDATE SET pubkey=excluded.pubkey, meta=excluded.meta, version=users.version+1
        """,
        (user_id, pubkey.decode("utf-8", errors="ignore"), "n/a", "n/a", meta_json),
    )
    await DB.commit()


async def add_public_member(user_id: str, wrapped_key: str) -> None:
    assert DB is not None, "store not initialised"
    await DB.execute(
        """
        INSERT INTO group_members(group_id, member_id, role, wrapped_key, added_at)
        VALUES(?, ?, ?, ?, ?)
        ON CONFLICT(group_id, member_id) DO UPDATE SET wrapped_key=excluded.wrapped_key, added_at=excluded.added_at
        """,
        ("public", user_id, "member", wrapped_key, int(time.time())),
    )
    await DB.commit()
