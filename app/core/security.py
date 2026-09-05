"""Security layer: passwords, sessions, integrity badges, server secrets.

Everything is built on the from-scratch crypto engine (no hashlib/cryptography).
- Passwords: PBKDF2-HMAC-SHA256 with a random 16-byte salt (nonce).
- Sessions: HMAC-signed tokens with >= 64 bits of entropy, stored hashed.
- Integrity badges: HMAC over record ciphertexts to detect tampering.
"""

import hmac
import json
import os
import secrets
import time

from ..crypto import hmac_sha256, pbkdf2_hmac_sha256, sha256, sha256_hex
from ..crypto.math_utils import random_bytes
from . import config

# --- Server secrets --------------------------------------------------------

def load_or_create_secret(path: str | None = None) -> str:
    """Load the server secret from disk, generating it on first boot."""
    path = path or config.SECRET_PATH
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    secret = random_bytes(32).hex()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(secret)
    return secret


def load_or_create_master_key(path: str | None = None) -> dict:
    """Load the server master RSA keypair, generating it on first boot.

    The master key wraps every user private key in the vault. It is stored on
    the server filesystem (never in the database).
    """
    from ..crypto import rsa
    path = path or config.MASTER_KEY_PATH
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    key = rsa.generate_rsa_keypair(3072)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(key, f)
    return key


# --- Passwords -------------------------------------------------------------
# The stored hash is self-describing so the KDF cost can change without
# invalidating existing passwords:
#   pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>

def hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    """Return (encoded_hash, salt_hex). The salt is a random 16-byte nonce."""
    salt = bytes.fromhex(salt_hex) if salt_hex else random_bytes(16)
    dk = pbkdf2_hmac_sha256(password.encode(), salt, config.PBKDF2_ITERATIONS, 32)
    encoded = f"pbkdf2_sha256${config.PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"
    return encoded, salt.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time password verification against a stored encoded hash.

    The iteration count and salt are read from the stored string, so raising
    the KDF cost later does not break existing accounts.
    """
    try:
        scheme, iterations, salt_hex, expected = stored_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        dk = pbkdf2_hmac_sha256(password.encode(), bytes.fromhex(salt_hex), int(iterations), 32)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk.hex(), expected)


# --- Sessions --------------------------------------------------------------

def generate_session_token() -> str:
    """Generate a session token with >= 64 bits of entropy (we use 256)."""
    return secrets.token_hex(32)


def sign_session_token(token: str, user_id: int, secret: str) -> str:
    """HMAC-sign a session token; the signature binds the token to the user."""
    sig = hmac_sha256(secret.encode(), f"{user_id}:{token}".encode()).hex()
    return f"{user_id}.{token}.{sig}"


def verify_session_token(signed: str, secret: str) -> int | None:
    """Verify an HMAC-signed session token; returns user_id or None."""
    try:
        user_id, token, sig = signed.split(".")
        expected = hmac_sha256(secret.encode(), f"{user_id}:{token}".encode()).hex()
        if not hmac.compare_digest(sig, expected):
            return None
        return int(user_id)
    except (ValueError, AttributeError):
        return None


def validate_session(ctx, signed: str):
    """Full session validation used by every protected endpoint.

    A token is valid only if (1) its HMAC signature checks out AND (2) a
    matching live session row exists in the ``sessions`` table (not expired)
    AND (3) the user is not suspended. Because the sessions row is required,
    deleting it — on logout, password change, suspension, or credential reset —
    immediately invalidates the token (true revocation).
    """
    if not ctx or not signed:
        return None
    user_id = verify_session_token(signed, ctx.secret)
    if user_id is None:
        return None
    try:
        _, raw, _ = signed.split(".")
    except (ValueError, AttributeError):
        return None
    row = ctx.db.fetchone(
        "SELECT expires_at FROM sessions WHERE token_hash = ? AND user_id = ?",
        (token_hash(raw), user_id))
    if row is None or row["expires_at"] < int(time.time()):
        return None
    urow = ctx.db.fetchone("SELECT id, username, role, is_suspended FROM users WHERE id = ?", (user_id,))
    if urow is None or urow["is_suspended"]:
        return None
    return urow


# --- Integrity badges ------------------------------------------------------

def make_integrity_badge(record_type: str, record_id: int, ciphertext: str, secret: str) -> str:
    """HMAC badge over a record's ciphertext to detect tampering."""
    payload = f"{record_type}:{record_id}:{ciphertext}".encode()
    return hmac_sha256(secret.encode(), payload).hex()


def verify_integrity_badge(record_type: str, record_id: int, ciphertext: str,
                           badge: str, secret: str) -> bool:
    """Constant-time integrity check; returns True if the record is intact."""
    expected = make_integrity_badge(record_type, record_id, ciphertext, secret)
    return hmac.compare_digest(badge, expected)


def log_integrity_failure(db, record_type: str, record_id: int, reason: str) -> None:
    """Record an HMAC verification failure in the system-wide log."""
    db.execute(
        "INSERT INTO integrity_log (record_type, record_id, reason, created_at) VALUES (?, ?, ?, ?)",
        (record_type, record_id, reason, int(time.time())))


# --- Misc ------------------------------------------------------------------

def token_hash(token: str) -> str:
    """Hash a session token before storing it in the database."""
    return sha256_hex(token.encode())


def entropy_bits(token: str) -> int:
    """Bits of entropy in a hex token (for the session-strength guarantee)."""
    return len(token) * 4