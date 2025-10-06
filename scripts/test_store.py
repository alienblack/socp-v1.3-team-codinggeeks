# scripts/test_store.py
import os, tempfile, sqlite3
from socp.core import store

def main():
    db_fd, db_path = tempfile.mkstemp(prefix="socp_store_", suffix=".db")
    os.close(db_fd)
    conn = None
    try:
        conn = store.connect(db_path)
        store.init_db(conn, "db/schema.sql")

        # ensure group + rotate once
        store.ensure_group(conn, "public")
        v1 = store.get_group_version(conn, "public"); assert v1 == 1
        k1 = store.get_group_key_b64u(conn, "public")

        v2 = store.bump_group_version(conn, "public"); assert v2 == 2
        k2 = store.get_group_key_b64u(conn, "public"); assert k1 != k2

        # add a user and membership (no wrap yet)
        store.put_user(conn, "user-alice", "PUBKEY_B64U_FAKE")
        store.add_member(conn, "public", "user-alice", wrapped_b64u=None)
        members = store.get_group_members(conn, "public"); assert "user-alice" in members

        # upsert a wrapped key
        store.store_wrapped_key(conn, "public", "user-alice", store.get_group_version(conn, "public"), "WRAP_FAKE")
        ver, wrap = store.get_wrapped_key(conn, "public", "user-alice")
        assert ver == store.get_group_version(conn, "public")
        assert wrap == "WRAP_FAKE"

        print("OK: store.py smoke test passed.")
    finally:
        try:
            if conn is not None:
                conn.close()
        finally:
            # On Windows you must close the connection before deleting the file.
            if os.path.exists(db_path):
                os.remove(db_path)

if __name__ == "__main__":
    main()
