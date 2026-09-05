"""Crypto engine tests: known vectors + roundtrips.

Run:  python -m pytest tests/test_crypto.py -v
"""

import time

from app.crypto import elgamal, rsa, totp
from app.crypto.math_utils import generate_prime, is_probable_prime
from app.crypto.sha256_hmac import (
    generate_totp_secret,
    hmac_sha256,
    pbkdf2_hmac_sha256,
    sha256,
    totp_code,
    verify_totp,
)


def test_sha256_vectors():
    assert sha256(b"").hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256(b"a" * 1_000_000).hex() == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"


def test_hmac_vector():
    key = bytes([0x0B] * 20)
    assert hmac_sha256(key, b"Hi There").hex() == \
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"


def test_pbkdf2_vector():
    v = pbkdf2_hmac_sha256(b"password", b"salt", 1, 32).hex()
    assert v == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"


def test_totp_self_consistency():
    secret = generate_totp_secret()
    t = int(time.time())
    code = totp_code(secret, t=t)
    assert verify_totp(secret, code, t=t)
    assert not verify_totp(secret, "999999", t=t)
    assert totp_code(secret, t=t) != totp_code(secret, t=t - 90)


def test_totp_30_second_window():
    secret = generate_totp_secret()
    t = int(time.time())
    code_prev = totp_code(secret, t=t - 30)
    code_curr = totp_code(secret, t=t)
    code_next = totp_code(secret, t=t + 30)
    code_too_old = totp_code(secret, t=t - 60)
    code_too_future = totp_code(secret, t=t + 60)

    # Previous 30s and next 30s are valid with current server time
    assert verify_totp(secret, code_prev, t=t)
    assert verify_totp(secret, code_curr, t=t)
    assert verify_totp(secret, code_next, t=t)

    # Codes beyond 30 seconds are rejected
    assert not verify_totp(secret, code_too_old, t=t)
    assert not verify_totp(secret, code_too_future, t=t)


def test_rsa_roundtrip_and_signature():
    kp = rsa.generate_rsa_keypair(1024)  # small key for test speed
    msg = b'{"email": "alice@example.com", "name": "Alice"}'
    ct = rsa.rsa_encrypt_bytes(kp, msg)
    assert rsa.rsa_decrypt_bytes(kp, ct) == msg
    sig = rsa.rsa_sign(kp, msg)
    assert rsa.rsa_verify(kp, msg, sig)
    assert not rsa.rsa_verify(kp, msg + b"x", sig)


def test_elgamal_roundtrip_multiblock(tmp_path):
    d = elgamal.generate_and_save_domain(str(tmp_path / "domain.json"), p_bits=512, q_bits=128)
    kp = d.generate_keypair()
    for m in (b"hi", b"IOC: 185.220.101.34 | CVE-2024-1234", b"x" * 200, b"x" * 201, b"x" * 500):
        ct = d.encrypt(kp["y"], m)
        assert d.decrypt(kp["x"], ct) == m


def test_prime_generation():
    p = generate_prime(256)
    assert is_probable_prime(p)
    assert p.bit_length() == 256