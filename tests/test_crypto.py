
import os
from socp.core import crypto
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def _gen_pub(size=4096):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=size)
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def test_accept_pubkey_strict_and_weak():
    pub4096 = _gen_pub(4096)
    pub1024 = _gen_pub(1024)
    os.environ["VULN_WEAK_KEYS"]="0"
    assert crypto.accept_pubkey(pub4096) is True
    assert crypto.accept_pubkey(pub1024) is False
    os.environ["VULN_WEAK_KEYS"]="1"
    assert crypto.accept_pubkey(pub1024) is True
