import os, base64
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64url_to_bytes(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

def rsa_encrypt_oaep(pubkey_pem: bytes, plaintext: bytes) -> bytes:
    pub = serialization.load_pem_public_key(pubkey_pem)
    return pub.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

def rsa_decrypt_oaep(privkey_pem: bytes, ciphertext: bytes) -> bytes:
    priv = serialization.load_pem_private_key(privkey_pem, password=None)
    return priv.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

def sign_pss_sha256(privkey_pem: bytes, msg: bytes) -> bytes:
    priv = serialization.load_pem_private_key(privkey_pem, password=None)
    return priv.sign(
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verify_pss_sha256(pubkey_pem: bytes, msg: bytes, sig: bytes) -> bool:
    pub = serialization.load_pem_public_key(pubkey_pem)
    try:
        pub.verify(
            sig,
            msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def _is_rsa_pubkey_strong(pub) -> bool:
    if not isinstance(pub, rsa.RSAPublicKey):
        return False
    return (pub.key_size >= 4096) and (pub.public_numbers().e == 65537)

def _is_rsa_pubkey_weak_allowed(pub) -> bool:
    if not isinstance(pub, rsa.RSAPublicKey):
        return False
    if os.getenv("VULN_WEAK_KEYS", "0") != "1":
        return False
    return pub.key_size >= 1024

def accept_pubkey(pubkey_pem: bytes) -> bool:
    pub = serialization.load_pem_public_key(pubkey_pem)
    return _is_rsa_pubkey_strong(pub) or _is_rsa_pubkey_weak_allowed(pub)

def content_sig_bytes(ciphertext: bytes, from_id: str, to_id: str, ts_ms: int) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(ciphertext)
    h.update(from_id.encode("utf-8"))
    h.update(to_id.encode("utf-8"))
    h.update(str(ts_ms).encode("utf-8"))
    return h.finalize()

def sign_content(privkey_pem: bytes, ciphertext: bytes, from_id: str, to_id: str, ts_ms: int) -> bytes:
    msg = content_sig_bytes(ciphertext, from_id, to_id, ts_ms)
    return sign_pss_sha256(privkey_pem, msg)

def verify_content(pubkey_pem: bytes, ciphertext: bytes, from_id: str, to_id: str, ts_ms: int, sig: bytes) -> bool:
    msg = content_sig_bytes(ciphertext, from_id, to_id, ts_ms)
    return verify_pss_sha256(pubkey_pem, msg, sig)
