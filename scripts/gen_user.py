
#!/usr/bin/env python3
import argparse, os, sys, json, sqlite3, time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import base64, uuid

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--server-db", default="socp.db")
    ap.add_argument("--weak-1024", action="store_true")
    ap.add_argument("--password", default="passw0rd")
    args = ap.parse_args()

    key_size = 1024 if args.weak_1024 else 4096
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # fake 'privkey_store' as clear for now (TODO: encrypt with PAKE-derived key)
    conn = sqlite3.connect(args.server_db)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users(user_id TEXT PRIMARY KEY, pubkey TEXT, privkey_store TEXT, pake_password TEXT, meta TEXT, version INTEGER)")
    user_id = str(uuid.uuid4())
    c.execute("INSERT OR REPLACE INTO users VALUES(?,?,?,?,?,?)",
              (user_id, pub_pem.decode(), priv_pem.decode(), 'pake-demo', json.dumps({"display_name": args.user}), 1))
    conn.commit()
    print(f"Created user {args.user} with id {user_id} (key_size={key_size}) in {args.server_db}")
if __name__ == "__main__":
    main()
