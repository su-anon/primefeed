"""Pure Python cryptography engine -- no external crypto libraries.

Implements, from scratch: SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256, RSA-3072
(with PKCS#1 v1.5), ElGamal (2048-bit Schnorr group), and TOTP.
"""

from . import elgamal, math_utils, rsa, sha256_hmac, totp  # noqa: F401
from .elgamal import ElGamalDomain, load_domain  # noqa: F401
from .math_utils import constant_time_eq, modinv, random_bytes, random_int  # noqa: F401
from .rsa import (  # noqa: F401
    generate_rsa_keypair,
    rsa_decrypt_bytes,
    rsa_encrypt_bytes,
    rsa_sign,
    rsa_verify,
)
from .sha256_hmac import (  # noqa: F401
    generate_totp_secret,
    hmac_sha256,
    pbkdf2_hmac_sha256,
    sha256,
    sha256_hex,
    totp_code,
    verify_totp,
)
from .totp import generate_totp_secret as _totp_secret  # noqa: F401