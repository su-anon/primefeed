"""SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256, and TOTP primitives.

In accordance with the CSE447 project specifications:
- Asymmetric encryption algorithms (RSA and ElGamal) are implemented from scratch.
- Non-encryption primitives (hashing, MACs, password derivation, and TOTP)
  leverage Python's standard library (`hashlib`, `hmac`, `secrets`) and `pyotp`
  for security, efficiency, and standards compliance.
"""

import base64
import hashlib
import hmac
import secrets
import time

import pyotp


def sha256(data: bytes) -> bytes:
    """Return the 32-byte SHA-256 digest of ``data`` (FIPS 180-4)."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Hex digest helper."""
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """Return the 32-byte HMAC-SHA256 of ``msg`` under ``key`` (RFC 2104)."""
    return hmac.new(key, msg, hashlib.sha256).digest()


def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    """Derive ``dklen`` key bytes from ``password`` and ``salt`` (RFC 8018)."""
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen)


# --- TOTP (RFC 6238) -------------------------------------------------------

def generate_totp_secret(nbytes: int = 20) -> str:
    """Generate a random base32 TOTP shared secret (160 bits default)."""
    return base64.b32encode(secrets.token_bytes(nbytes)).decode()


def totp_code(secret_b32: str, digits: int = 6, time_step: int = 30, t: int | None = None) -> str:
    """Current TOTP code. ``t`` overrides the Unix time (for tests)."""
    if t is None:
        t = int(time.time())
    totp = pyotp.TOTP(secret_b32, digits=digits, interval=time_step, digest=hashlib.sha256)
    return totp.at(t)


def verify_totp(secret_b32: str, code: str, digits: int = 6, time_step: int = 30,
                window: int = 1, t: int | None = None) -> bool:
    """Verify a TOTP code against the current time, allowing +/- window (30s) steps.

    With window=1 and time_step=30, the previous 30s (-30s), current, and next
    30s (+30s) intervals are all accepted. Supports both SHA-256 and SHA-1
    (standard mobile authenticators like Google Authenticator).
    """
    if t is None:
        t = int(time.time())
    code_str = str(code).strip()
    # 1. Primary: SHA-256
    totp256 = pyotp.TOTP(secret_b32, digits=digits, interval=time_step, digest=hashlib.sha256)
    if totp256.verify(code_str, for_time=t, valid_window=window):
        return True
    # 2. Fallback: SHA-1 for mobile authenticator apps
    totp1 = pyotp.TOTP(secret_b32, digits=digits, interval=time_step, digest=hashlib.sha1)
    if totp1.verify(code_str, for_time=t, valid_window=window):
        return True
    return False