"""TOTP (RFC 6238) -- re-exported from the sha256_hmac module.

Kept as a separate module so ``from app.crypto import totp`` reads naturally.
"""

from .sha256_hmac import generate_totp_secret, totp_code, verify_totp  # noqa: F401