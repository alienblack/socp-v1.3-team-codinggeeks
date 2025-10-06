import json
import time
from pathlib import Path
from typing import Any, Optional

import aiosqlite

DB: Optional[aiosqlite.Connection] = None

ROOT = Path(__file__).resolve().parents[2]
KEY_DIRS = (
    ROOT,
    ROOT / "configs",
    ROOT / "configs" / "keys",
)


def _ensure_db() -> aiosqlite.Connection:
    if DB is None:
        raise RuntimeError("store.init() must be awaited before use")
    return DB


def _normalise_meta(meta: Optional[Any]) -> Optional[str]:
    if meta is None:
        return None
    if isinstance(meta, str):
        return meta
    return json.dumps(meta)


def _coerce_pubkey(value: Any) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


def _load_pubkey_from_disk(user_id: str) -> Optional[bytes]:
    candidate_name = f"{user_id}_public.pem"
    for base in KEY_DIRS:
        path = (base / candidate_name).resolve()
        try:
            if path.is_file():
                return path.read_bytes()
        except OSError:
            continue
    return None


async def init(path: str = "socp.db") -> None:
    global DB
    if DB is not None:
        await DB.close()

    db_path = Path(path)
    if db_path.parent and not db_path.parent.exists():
        db_path.parent.mkdir(parents=True, exist_ok=True)

    DB = await aiosqlite.connect(db_path)
    DB.row_factory = aiosqlite.Row

    await DB.execute("PRAGMA foreign_keys=ON")

    schema_path = ROOT / "db" / "schema.sql"
    await DB.executescript(schema_path.read_text(encoding="utf-8"))

    seed_path = ROOT / "db" / "seed.sql"
    if seed_path.exists():
        seed_sql = seed_path.read_text(encoding="utf-8").strip()
        if seed_sql:
            await DB.executescript(seed_sql)

    await DB.commit()


async def ensure_public_group() -> None:
    db = _ensure_db()
    cur = await db.execute("SELECT 1 FROM groups WHERE group_id=?", ("public",))
    row = await cur.fetchone()
    await cur.close()
    if row:
        return
    await db.execute(
        "INSERT INTO groups(group_id, creator_id, created_at, meta, version) VALUES(?,?,?,?,?)",
        ("public", "system", int(time.time() * 1000), json.dumps({"title": "Public"}), 1),
    )
    await db.commit()


async def upsert_user(
    user_id: str,
    pubkey_pem: bytes | str,
    *,
    privkey_store: str = "",
    pake_password: str = "",
    meta: Optional[Any] = None,
    version: int = 1,
) -> None:
    db = _ensure_db()
    if isinstance(pubkey_pem, bytes):
        pubkey_text = pubkey_pem.decode("utf-8")
    else:
        pubkey_text = str(pubkey_pem)

    await db.execute(
        """
        INSERT INTO users(user_id, pubkey, privkey_store, pake_password, meta, version)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(user_id) DO UPDATE SET
            pubkey=excluded.pubkey,
            privkey_store=excluded.privkey_store,
            pake_password=excluded.pake_password,
            meta=excluded.meta,
            version=excluded.version
        """,
        (
            user_id,
            pubkey_text,
            privkey_store or "",
            pake_password or "",
            _normalise_meta(meta),
            int(version),
        ),
    )
    await db.commit()


async def get_user_pubkey(user_id: str) -> Optional[bytes]:
    db = _ensure_db()
    cur = await db.execute("SELECT pubkey FROM users WHERE user_id=?", (user_id,))
    row = await cur.fetchone()
    await cur.close()
    if row and row[0]:
        return _coerce_pubkey(row[0])

    disk_value = _load_pubkey_from_disk(user_id)
    if disk_value:
        await upsert_user(user_id, disk_value, privkey_store="(disk)", pake_password="")
        return disk_value

    return None


async def close() -> None:
    global DB
    if DB is not None:
        await DB.close()
        DB = None
