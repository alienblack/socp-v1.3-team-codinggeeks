from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(slots=True)
class RSAKeyPair:
    """Convenience wrapper for RSA key pairs."""

    private_pem: bytes
    public_pem: bytes


def b64url(data: bytes) -> str:
    """Return base64url (unpadded) encoding of *data*."""

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    """Decode an unpadded base64url string."""

    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - defensive path
        raise ValueError("invalid base64url") from exc


def generate_rsa_keypair(key_size: int = 4096) -> RSAKeyPair:
    """Generate an RSA key pair (OAEP/PSS compatible)."""

    private = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return RSAKeyPair(private_pem=private_pem, public_pem=public_pem)


def load_private_key(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None, backend=default_backend())


def load_public_key(pem: bytes):
    return serialization.load_pem_public_key(pem, backend=default_backend())


def rsa_encrypt_oaep(pubkey_pem: bytes, plaintext: bytes) -> bytes:
    pub = load_public_key(pubkey_pem)
    return pub.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt_oaep(privkey_pem: bytes, ciphertext: bytes) -> bytes:
    priv = load_private_key(privkey_pem)
    return priv.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def sign_pss_sha256(privkey_pem: bytes, msg: bytes) -> bytes:
    priv = load_private_key(privkey_pem)
    return priv.sign(
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_pss_sha256(pubkey_pem: bytes, msg: bytes, sig: bytes) -> bool:
    pub = load_public_key(pubkey_pem)
    try:
        pub.verify(
            sig,
            msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def _key_size(pubkey_pem: bytes) -> int:
    pub = load_public_key(pubkey_pem)
    if isinstance(pub, rsa.RSAPublicKey):
        return pub.key_size
    return 0


def accept_pubkey(pubkey_pem: bytes) -> bool:
    """Validate the RSA key size, honouring the VULN_WEAK_KEYS toggle."""

    allow_weak = os.getenv("VULN_WEAK_KEYS", "0") == "1"
    size = _key_size(pubkey_pem)
    if allow_weak and size >= 1024:
        return True
    return size >= 4096


def _sha256_concat(*parts: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    for part in parts:
        digest.update(part)
    return digest.finalize()


def content_digest_direct(ciphertext: bytes, from_id: str, to_id: str, ts: int) -> bytes:
    return _sha256_concat(ciphertext, from_id.encode(), to_id.encode(), str(ts).encode())


def content_digest_public(ciphertext: bytes, from_id: str, ts: int) -> bytes:
    return _sha256_concat(ciphertext, from_id.encode(), str(ts).encode())


def content_digest_key_share(shares_blob: bytes, creator_pub: bytes) -> bytes:
    return _sha256_concat(shares_blob, creator_pub)


def verify_content_signature(pubkey_pem: bytes, digest: bytes, signature_b64: str) -> bool:
    try:
        sig = b64url_decode(signature_b64)
    except ValueError:
        return False
    return verify_pss_sha256(pubkey_pem, digest, sig)


def sign_content(privkey_pem: bytes, digest: bytes) -> str:
    return b64url(sign_pss_sha256(privkey_pem, digest))


def ensure_rsa_pair(private_pem_path: str, public_pem_path: str) -> RSAKeyPair:
    """Load an RSA key pair from disk, generating if the files are missing."""

    priv_path = os.fspath(private_pem_path)
    pub_path = os.fspath(public_pem_path)
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        private_pem = open(priv_path, "rb").read()
        public_pem = open(pub_path, "rb").read()
        return RSAKeyPair(private_pem=private_pem, public_pem=public_pem)

    Path(priv_path).parent.mkdir(parents=True, exist_ok=True)
    Path(pub_path).parent.mkdir(parents=True, exist_ok=True)
    pair = generate_rsa_keypair()
    with open(priv_path, "wb") as priv_file:
        priv_file.write(pair.private_pem)
    with open(pub_path, "wb") as pub_file:
        pub_file.write(pair.public_pem)
    return pair

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    if len(key) not in {16, 24, 32}:
        raise ValueError("invalid AES key length")
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def aes_gcm_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(key) not in {16, 24, 32}:
        raise ValueError("invalid AES key length")
    nonce, ciphertext = blob[:12], blob[12:]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, aad)




