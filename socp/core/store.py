# socp/core/store.py
# SQLite persistence helpers for users, groups, memberships, and per-user wrapped keys.
# Designed for the SOCP public-channel flow.

from __future__ import annotations
import os
import time
import base64
import sqlite3
from typing import Dict, Iterable, List, Optional, Tuple

# ---------- small utils ----------

def _now_ms() -> int:
    return int(time.time() * 1000)

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _rand_key_32_b64u() -> str:
    # 256-bit random symmetric key (base64url)
    return _b64u(os.urandom(32))

# ---------- connection & schema ----------

def connect(db_path: str) -> sqlite3.Connection:
    """
    Open (and create) the SQLite database with foreign keys enabled.
    Autocommit mode is used for simplicity.
    """
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(conn: sqlite3.Connection, schema_path: str = "db/schema.sql") -> None:
    """
    Apply the SQL schema from disk.
    """
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

# ---------- users ----------

def put_user(conn: sqlite3.Connection, user_id: str, pubkey_b64u: str) -> None:
    """
    Insert or update a user and their public key.
    """
    conn.execute(
        """
        INSERT INTO users(user_id, pubkey_b64u, created_at)
        VALUES(?,?,?)
        ON CONFLICT(user_id) DO UPDATE SET
            pubkey_b64u=excluded.pubkey_b64u
        """,
        (user_id, pubkey_b64u, _now_ms()),
    )

def get_user_pub(conn: sqlite3.Connection, user_id: str) -> Optional[str]:
    row = conn.execute("SELECT pubkey_b64u FROM users WHERE user_id=?", (user_id,)).fetchone()
    return row[0] if row else None

def list_users(conn: sqlite3.Connection) -> List[str]:
    return [r[0] for r in conn.execute("SELECT user_id FROM users ORDER BY user_id").fetchall()]

# ---------- groups & group keys ----------

def ensure_group(conn: sqlite3.Connection, group_id: str) -> None:
    """
    Ensure a logical group exists and has a current symmetric key.
    Creates the group at version=1 and a fresh 256-bit key if missing.
    """
    cur = conn.execute("SELECT 1 FROM groups WHERE group_id=?", (group_id,)).fetchone()
    if not cur:
        conn.execute(
            "INSERT INTO groups(group_id, version, created_at) VALUES(?,?,?)",
            (group_id, 1, _now_ms()),
        )
    # ensure a key entry exists
    cur = conn.execute("SELECT 1 FROM group_keys WHERE group_id=?", (group_id,)).fetchone()
    if not cur:
        conn.execute(
            "INSERT INTO group_keys(group_id, key_b64u, updated_at) VALUES(?,?,?)",
            (group_id, _rand_key_32_b64u(), _now_ms()),
        )

def get_group_version(conn: sqlite3.Connection, group_id: str) -> int:
    row = conn.execute("SELECT version FROM groups WHERE group_id=?", (group_id,)).fetchone()
    if not row:
        raise KeyError(f"group not found: {group_id}")
    return int(row[0])

def get_group_key_b64u(conn: sqlite3.Connection, group_id: str) -> str:
    row = conn.execute("SELECT key_b64u FROM group_keys WHERE group_id=?", (group_id,)).fetchone()
    if not row:
        raise KeyError(f"group key not found: {group_id}")
    return row[0]

def bump_group_version(conn: sqlite3.Connection, group_id: str) -> int:
    """
    Rotate the group's symmetric key and increment version.
    Wrapped keys are invalidated (deleted) so they must be re-wrapped for members.
    Returns the new version number.
    """
    new_ver = get_group_version(conn, group_id) + 1
    conn.execute("UPDATE groups SET version=? WHERE group_id=?", (new_ver, group_id))
    conn.execute(
        "UPDATE group_keys SET key_b64u=?, updated_at=? WHERE group_id=?",
        (_rand_key_32_b64u(), _now_ms(), group_id),
    )
    # invalidate existing wraps so they get regenerated under the new version
    conn.execute("DELETE FROM wrapped_keys WHERE group_id=?", (group_id,))
    return new_ver

def list_groups(conn: sqlite3.Connection) -> List[str]:
    return [r[0] for r in conn.execute("SELECT group_id FROM groups ORDER BY group_id").fetchall()]

# ---------- memberships & wrapped keys ----------

def add_member(
    conn: sqlite3.Connection,
    group_id: str,
    user_id: str,
    wrapped_b64u: Optional[str],
    version: Optional[int] = None,
) -> None:
    """
    Add user to a group (idempotent). Optionally store a wrapped key at the current version.
    """
    ensure_group(conn, group_id)
    # membership
    conn.execute(
        """
        INSERT INTO memberships(group_id, user_id, joined_at)
        VALUES(?,?,?)
        ON CONFLICT(group_id, user_id) DO NOTHING
        """,
        (group_id, user_id, _now_ms()),
    )
    # wrapped key
    if wrapped_b64u is not None:
        if version is None:
            version = get_group_version(conn, group_id)
        conn.execute(
            """
            INSERT INTO wrapped_keys(group_id, user_id, version, wrapped_b64u)
            VALUES(?,?,?,?)
            ON CONFLICT(group_id, user_id) DO UPDATE SET
                version=excluded.version,
                wrapped_b64u=excluded.wrapped_b64u
            """,
            (group_id, user_id, version, wrapped_b64u),
        )

def store_wrapped_key(
    conn: sqlite3.Connection, group_id: str, user_id: str, version: int, wrapped_b64u: str
) -> None:
    """
    Upsert the per-user wrapped key for a group and version.
    """
    conn.execute(
        """
        INSERT INTO wrapped_keys(group_id, user_id, version, wrapped_b64u)
        VALUES(?,?,?,?)
        ON CONFLICT(group_id, user_id) DO UPDATE SET
            version=excluded.version,
            wrapped_b64u=excluded.wrapped_b64u
        """,
        (group_id, user_id, version, wrapped_b64u),
    )

def get_group_members(conn: sqlite3.Connection, group_id: str) -> List[str]:
    return [r[0] for r in conn.execute(
        "SELECT user_id FROM memberships WHERE group_id=? ORDER BY user_id", (group_id,)
    ).fetchall()]

def get_wrapped_key(conn: sqlite3.Connection, group_id: str, user_id: str) -> Optional[Tuple[int, str]]:
    """
    Return (version, wrapped_b64u) for a specific member if present.
    """
    row = conn.execute(
        "SELECT version, wrapped_b64u FROM wrapped_keys WHERE group_id=? AND user_id=?",
        (group_id, user_id),
    ).fetchone()
    return (int(row[0]), row[1]) if row else None

def get_wrapped_keys_for_group(conn: sqlite3.Connection, group_id: str) -> Dict[str, Tuple[int, str]]:
    """
    Mapping: user_id -> (version, wrapped_b64u)
    """
    rows = conn.execute(
        "SELECT user_id, version, wrapped_b64u FROM wrapped_keys WHERE group_id=?",
        (group_id,),
    ).fetchall()
    return {user_id: (int(ver), wrapped) for (user_id, ver, wrapped) in rows}

def remove_member(conn: sqlite3.Connection, group_id: str, user_id: str) -> None:
    """
    Remove user from group and delete their wrapped key.
    """
    conn.execute("DELETE FROM memberships WHERE group_id=? AND user_id=?", (group_id, user_id))
    conn.execute("DELETE FROM wrapped_keys WHERE group_id=? AND user_id=?", (group_id, user_id))

# ---------- convenience for "public" group ----------

PUBLIC_GROUP_ID = "public"

def ensure_public(conn: sqlite3.Connection) -> None:
    ensure_group(conn, PUBLIC_GROUP_ID)

def public_version(conn: sqlite3.Connection) -> int:
    return get_group_version(conn, PUBLIC_GROUP_ID)

def public_key_b64u(conn: sqlite3.Connection) -> str:
    return get_group_key_b64u(conn, PUBLIC_GROUP_ID)
