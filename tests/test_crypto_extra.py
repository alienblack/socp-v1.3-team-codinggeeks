from socp.core import crypto
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

def _gen(bits):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
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

def test_decrypt_and_verify_dm():
    s_priv, s_pub = _gen(4096)
    r_priv, r_pub = _gen(4096)
    msg = b"hello"
    ct = crypto.rsa_encrypt_oaep(r_pub, msg)
    sig = crypto.sign_content(s_priv, ct, "alice", "bob", 1695800000000)
    pt = crypto.decrypt_and_verify_dm(s_pub, r_priv, crypto.b64url(ct), "alice","bob",1695800000000, crypto.b64url(sig))
    assert pt == msg
    # tamper
    bad = crypto.decrypt_and_verify_dm(s_pub, r_priv, crypto.b64url(ct+b"!"), "alice","bob",1695800000000, crypto.b64url(sig))
    assert bad is None

def test_key_policy_boundary():
    _, pub3072 = _gen(3072)
    _, pub4096 = _gen(4096)
    os.environ["VULN_WEAK_KEYS"] = "0"
    assert crypto.accept_pubkey(pub4096) is True
    assert crypto.accept_pubkey(pub3072) is False
    os.environ["VULN_WEAK_KEYS"] = "1"
    assert crypto.accept_pubkey(pub4096) is True
