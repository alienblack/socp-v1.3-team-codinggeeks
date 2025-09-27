
import os, base64, json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def rsa_encrypt_oaep(pubkey_pem: bytes, plaintext: bytes) -> bytes:
    pub = serialization.load_pem_public_key(pubkey_pem)
    return pub.encrypt(plaintext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def rsa_decrypt_oaep(privkey_pem: bytes, ciphertext: bytes) -> bytes:
    priv = serialization.load_pem_private_key(privkey_pem, password=None)
    return priv.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def sign_pss_sha256(privkey_pem: bytes, msg: bytes) -> bytes:
    priv = serialization.load_pem_private_key(privkey_pem, password=None)
    return priv.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

def verify_pss_sha256(pubkey_pem: bytes, msg: bytes, sig: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    pub = serialization.load_pem_public_key(pubkey_pem)
    try:
        pub.verify(sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except InvalidSignature:
        return False

def accept_pubkey(pubkey_pem: bytes) -> bool:
    # Backdoor: accept weak keys when VULN_WEAK_KEYS=1
    allow_weak = os.getenv("VULN_WEAK_KEYS","0") == "1"
    pub = serialization.load_pem_public_key(pubkey_pem)
    if isinstance(pub, rsa.RSAPublicKey):
        key_size = pub.key_size
        if allow_weak and key_size >= 1024:
            return True
        return key_size >= 4096
    return False
