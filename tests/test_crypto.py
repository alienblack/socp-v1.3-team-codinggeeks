import os
from socp.core import crypto
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def _gen_key(size=4096):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=size)
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem

def test_accept_pubkey_strict_and_weak():
    _, pub4096 = _gen_key(4096)
    _, pub1024 = _gen_key(1024)

    os.environ["VULN_WEAK_KEYS"] = "0"
    assert crypto.accept_pubkey(pub4096) is True
    assert crypto.accept_pubkey(pub1024) is False

    os.environ["VULN_WEAK_KEYS"] = "1"
    assert crypto.accept_pubkey(pub1024) is True

def test_pss_sign_verify_and_tamper():
    priv, pub = _gen_key(4096)
    msg = b"hello world"
    sig = crypto.sign_pss_sha256(priv, msg)
    assert crypto.verify_pss_sha256(pub, msg, sig) is True
    assert crypto.verify_pss_sha256(pub, msg + b"!", sig) is False

def test_oaep_encrypt_decrypt_roundtrip():
    priv, pub = _gen_key(4096)
    pt = b"secret bytes"
    ct = crypto.rsa_encrypt_oaep(pub, pt)
    rt = crypto.rsa_decrypt_oaep(priv, ct)
    assert rt == pt

def test_content_signature():
    priv, pub = _gen_key(4096)
    ct = b"...ciphertext..."
    from_id = "alice"
    to_id = "bob"
    ts = 1695800000000
    sig = crypto.sign_content(priv, ct, from_id, to_id, ts)
    assert crypto.verify_content(pub, ct, from_id, to_id, ts, sig) is True
    assert crypto.verify_content(pub, ct + b"!", from_id, to_id, ts, sig) is False
