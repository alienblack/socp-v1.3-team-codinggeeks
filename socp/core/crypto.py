"""Cryptographic primitives and helpers for SOCP."""
from __future__ import annotations

import base64
import binascii
import os
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

__all__ = [
    "b64url",
    "b64url_to_bytes",
    "rsa_encrypt_oaep",
    "rsa_decrypt_oaep",
    "sign_pss_sha256",
    "verify_pss_sha256",
    "accept_pubkey",
    "content_sig_bytes",
    "sign_content",
    "verify_content",
    "decrypt_and_verify_dm",
    "generate_rsa_keypair",
    "save_pem",
    "load_pem",
]


# ---------------------------------------------------------------------------
# Base64 helpers
# ---------------------------------------------------------------------------

def b64url(data: bytes) -> str:
    """Return URL-safe base64 without padding."""

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_to_bytes(token: str) -> bytes:
    """Decode a URL-safe base64 string that may omit padding."""

    pad_len = (-len(token)) % 4
    return base64.urlsafe_b64decode(token + "=" * pad_len)


# ---------------------------------------------------------------------------
# RSA primitives
# ---------------------------------------------------------------------------

def _load_public_key(pubkey_pem: bytes) -> rsa.RSAPublicKey:
    pub = serialization.load_pem_public_key(pubkey_pem)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError("Expected an RSA public key")
    return pub


def _load_private_key(privkey_pem: bytes) -> rsa.RSAPrivateKey:
    priv = serialization.load_pem_private_key(privkey_pem, password=None)
    if not isinstance(priv, rsa.RSAPrivateKey):
        raise TypeError("Expected an RSA private key")
    return priv


def rsa_encrypt_oaep(pubkey_pem: bytes, plaintext: bytes) -> bytes:
    """Encrypt ``plaintext`` with RSA-OAEP (SHA-256)."""

    pub = _load_public_key(pubkey_pem)
    return pub.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt_oaep(privkey_pem: bytes, ciphertext: bytes) -> bytes:
    """Decrypt RSA-OAEP ciphertext using ``privkey_pem``."""

    priv = _load_private_key(privkey_pem)
    return priv.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def sign_pss_sha256(privkey_pem: bytes, message: bytes) -> bytes:
    """Sign ``message`` with RSASSA-PSS using SHA-256."""

    priv = _load_private_key(privkey_pem)
    return priv.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_pss_sha256(pubkey_pem: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a RSASSA-PSS signature."""

    pub = _load_public_key(pubkey_pem)
    try:
        pub.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Key acceptance policy
# ---------------------------------------------------------------------------

_STRICT_EXPONENT = 65537
_STRICT_KEY_SIZE = 4096
_WEAK_MIN_KEY_SIZE = 1024


def _weak_keys_allowed() -> bool:
    return os.getenv("VULN_WEAK_KEYS", "0") == "1"


def _is_strong_rsa_key(pub: rsa.RSAPublicKey) -> bool:
    return pub.key_size >= _STRICT_KEY_SIZE and pub.public_numbers().e == _STRICT_EXPONENT


def _is_allowed_weak_key(pub: rsa.RSAPublicKey) -> bool:
    return _weak_keys_allowed() and pub.key_size >= _WEAK_MIN_KEY_SIZE


def accept_pubkey(pubkey_pem: bytes) -> bool:
    """Return ``True`` if the PEM represents an acceptable RSA public key."""

    try:
        pub = _load_public_key(pubkey_pem)
    except (ValueError, TypeError):
        return False
    return _is_strong_rsa_key(pub) or _is_allowed_weak_key(pub)


# ---------------------------------------------------------------------------
# Content signature helpers
# ---------------------------------------------------------------------------

def content_sig_bytes(ciphertext: bytes, from_id: str, to_id: str, ts_ms: int) -> bytes:
    """Return the SHA-256 digest used for DM/group content signatures."""

    digest = hashes.Hash(hashes.SHA256())
    digest.update(ciphertext)
    digest.update(from_id.encode("utf-8"))
    digest.update(to_id.encode("utf-8"))
    digest.update(str(ts_ms).encode("utf-8"))
    return digest.finalize()


def sign_content(
    privkey_pem: bytes,
    ciphertext: bytes,
    from_id: str,
    to_id: str,
    ts_ms: int,
) -> bytes:
    """Sign a DM/group payload using the configured content signature format."""

    message = content_sig_bytes(ciphertext, from_id, to_id, ts_ms)
    return sign_pss_sha256(privkey_pem, message)


def verify_content(
    pubkey_pem: bytes,
    ciphertext: bytes,
    from_id: str,
    to_id: str,
    ts_ms: int,
    signature: bytes,
) -> bool:
    """Verify a DM/group content signature."""

    message = content_sig_bytes(ciphertext, from_id, to_id, ts_ms)
    return verify_pss_sha256(pubkey_pem, message, signature)


def decrypt_and_verify_dm(
    sender_pub_pem: bytes,
    recipient_priv_pem: bytes,
    b64_ciphertext: str,
    from_id: str,
    to_id: str,
    ts_ms: int,
    b64_content_sig: str,
) -> bytes | None:
    """Verify a content signature before decrypting a direct message."""

    try:
        ciphertext = b64url_to_bytes(b64_ciphertext)
        signature = b64url_to_bytes(b64_content_sig)
    except (ValueError, binascii.Error):
        return None

    if not verify_content(sender_pub_pem, ciphertext, from_id, to_id, ts_ms, signature):
        return None

    try:
        return rsa_decrypt_oaep(recipient_priv_pem, ciphertext)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Keypair generation and persistence helpers
# ---------------------------------------------------------------------------

def generate_rsa_keypair(bits: int = _STRICT_KEY_SIZE) -> Tuple[bytes, bytes]:
    """Generate an RSA keypair, defaulting to the strict policy."""

    private_key = rsa.generate_private_key(public_exponent=_STRICT_EXPONENT, key_size=bits)
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def save_pem(path: str, pem: bytes) -> None:
    """Persist a PEM blob to ``path``."""

    with open(path, "wb") as handle:
        handle.write(pem)


def load_pem(path: str) -> bytes:
    """Read a PEM blob from ``path``."""

    with open(path, "rb") as handle:
        return handle.read()
