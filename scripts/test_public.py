# scripts/test_public.py
import os, tempfile
from socp.core import store, public

def main():
    fd, db_path = tempfile.mkstemp(prefix="socp_public_", suffix=".db")
    os.close(fd)
    conn = None
    try:
        conn = store.connect(db_path)
        store.init_db(conn, "db/schema.sql")

        # Ensure public exists
        public.ensure_public(conn)
        assert store.public_version(conn) == 1

        # Fake user with fake pubkey (PEM b64u). For a smoke, we can just reuse any b64u string;
        # in full tests, use a real RSA pem b64u. Here, call crypto generator from scripts if available.
        from socp.core.crypto import gen_rsa4096_b64u  # if your crypto module exposes this
    except Exception:
        # fallback: generate a real keypair locally if helper not present
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_b64u = __import__("base64").urlsafe_b64encode(pub_pem).rstrip(b"=").decode()
    else:
        # if helper existed
        pub_b64u = gen_rsa4096_b64u()[1]  # (priv_b64u, pub_b64u)

    # add user & wrap
    ver, wrap = public.add_public_member(conn, "user-alice", pub_b64u)
    assert ver == store.public_version(conn)
    assert public.get_public_wrap_for(conn, "user-alice")[1] == wrap

    # rotate & ensure wraps regenerated
    new_ver = public.bump_public_version(conn)
    assert new_ver == store.public_version(conn)
    v2, wrap2 = public.get_public_wrap_for(conn, "user-alice")
    assert v2 == new_ver
    assert wrap2 != wrap  # wrap should change after rotation

    print("OK: public.py smoke test passed.")
    if conn:
        conn.close()
    os.remove(db_path)

if __name__ == "__main__":
    main()
