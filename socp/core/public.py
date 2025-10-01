# socp/core/public.py
# Public-channel group management for SOCP.
# - Ensure the "public" group exists
# - On user join: add to "public" and store RSA-OAEP wrapped group key
# - On rotation/version bump: regenerate wraps for all members

from __future__ import annotations
import base64
from typing import Dict, List, Tuple, Optional

from . import store

# Use cryptography directly for RSA-OAEP wrapping (independent of other modules)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# --------- small helpers ---------

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))

def _rsa_oaep_encrypt_b64(pub_pem_b64u: str, plaintext_b64u: str) -> str:
    """
    Encrypt the (base64url) plaintext bytes with RSA-OAEP(SHA-256) using recipient's public key (PEM in base64url).
    Returns base64url ciphertext.
    """
    pub = load_pem_public_key(_unb64u(pub_pem_b64u))
    pt = _unb64u(plaintext_b64u)
    ct = pub.encrypt(
        pt,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return _b64u(ct)

# --------- core API ---------

def ensure_public(conn) -> None:
    """Create the public group and a fresh symmetric key if missing."""
    store.ensure_public(conn)

def add_public_member(conn, user_id: str, user_pubkey_b64u: str) -> Tuple[int, str]:
    """
    Idempotently:
      - ensure public group exists
      - upsert the user and add membership
      - wrap the current public group key with the user's pubkey and store it

    Returns: (public_group_version, wrapped_key_b64u)
    """
    ensure_public(conn)
    # Save/refresh the user's pubkey
    store.put_user(conn, user_id, user_pubkey_b64u)

    ver = store.public_version(conn)
    gkey_b64u = store.public_key_b64u(conn)
    wrapped_b64u = _rsa_oaep_encrypt_b64(user_pubkey_b64u, gkey_b64u)

    store.add_member(conn, store.PUBLIC_GROUP_ID, user_id, wrapped_b64u=wrapped_b64u, version=ver)
    return ver, wrapped_b64u

def get_public_wrap_for(conn, user_id: str) -> Optional[Tuple[int, str]]:
    """Return (version, wrapped_b64u) for a specific public-group member, if present."""
    return store.get_wrapped_key(conn, store.PUBLIC_GROUP_ID, user_id)

def get_public_recipients_with_wraps(conn) -> Dict[str, Tuple[int, str]]:
    """
    Mapping: user_id -> (version, wrapped_b64u) for all members of the public group.
    Useful for fan-out of /all messages.
    """
    return store.get_wrapped_keys_for_group(conn, store.PUBLIC_GROUP_ID)

def bump_public_version(conn) -> int:
    """
    Rotate the public group's symmetric key and regenerate wraps for all members.
    Returns the new version.
    """
    new_ver = store.bump_group_version(conn, store.PUBLIC_GROUP_ID)
    # Re-wrap for all current members with the new key
    gkey_b64u = store.public_key_b64u(conn)
    for user_id in store.get_group_members(conn, store.PUBLIC_GROUP_ID):
        pub_b64u = store.get_user_pub(conn, user_id)
        if not pub_b64u:
            # user doesn't have a recorded pubkey; skip (shouldn't happen if add_public_member is used)
            continue
        wrapped_b64u = _rsa_oaep_encrypt_b64(pub_b64u, gkey_b64u)
        store.store_wrapped_key(conn, store.PUBLIC_GROUP_ID, user_id, new_ver, wrapped_b64u)
    return new_ver
