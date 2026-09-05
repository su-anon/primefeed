"""From-scratch SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256, and TOTP.

No hashlib, no cryptography package: only Python's native integers and bytes.

- SHA-256: FIPS 180-4 (padding, message schedule, 64-round compression).
- HMAC: RFC 2104 keyed hashing, used for session signing and integrity badges.
- PBKDF2: RFC 8018 salted key derivation, used for password hashing.
- TOTP: RFC 6238 time-based one-time passwords, used for mandatory 2FA.
"""

import base64
import os
import time

from .math_utils import constant_time_eq, random_bytes

_K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)

_H0 = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)

_MASK32 = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    """Rotate a 32-bit word right by n bits."""
    return ((x >> n) | (x << (32 - n))) & _MASK32


def sha256(data: bytes) -> bytes:
    """Return the 32-byte SHA-256 digest of ``data`` (FIPS 180-4)."""
    bit_len = len(data) * 8

    # --- Padding (Section 5.1.1) -------------------------------------------
    padded = data + b"\x80"
    padded += b"\x00" * ((56 - len(padded) % 64) % 64)
    padded += bit_len.to_bytes(8, "big")

    h = list(_H0)

    # --- Process each 64-byte block ----------------------------------------
    for off in range(0, len(padded), 64):
        block = padded[off:off + 64]

        # Message schedule: W[0..15] from the block, W[16..63] derived
        w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
        w += [0] * 48
        for t in range(16, 64):
            s0 = _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
            s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
            w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & _MASK32

        # Compression function
        a, b, c, d, e, f, g, hh = h
        for t in range(64):
            s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (hh + s1 + ch + _K[t] + w[t]) & _MASK32
            s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & _MASK32
            hh, g, f, e = g, f, e, (d + temp1) & _MASK32
            d, c, b, a = c, b, a, (temp1 + temp2) & _MASK32

        h = [(_h + v) & _MASK32 for _h, v in zip(h, (a, b, c, d, e, f, g, hh))]

    return b"".join(x.to_bytes(4, "big") for x in h)


def sha256_hex(data: bytes) -> str:
    """Hex digest helper."""
    return sha256(data).hex()


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """Return the 32-byte HMAC-SHA256 of ``msg`` under ``key`` (RFC 2104)."""
    block_size = 64  # SHA-256 block size
    if len(key) > block_size:
        key = sha256(key)
    key = key + b"\x00" * (block_size - len(key))

    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)

    return sha256(opad + sha256(ipad + msg))


def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    """Derive ``dklen`` key bytes from ``password`` and ``salt`` (RFC 8018).

    F(P, S, c, i) = U1 ^ U2 ^ ... ^ Uc where
    U1 = HMAC(P, S || INT_32_BE(i)) and Uc = HMAC(P, Uc-1).
    """
    hlen = 32  # SHA-256 output length
    n_blocks = (dklen + hlen - 1) // hlen
    out = b""

    for i in range(1, n_blocks + 1):
        u = hmac_sha256(password, salt + i.to_bytes(4, "big"))
        acc = u
        for _ in range(iterations - 1):
            u = hmac_sha256(password, u)
            acc = bytes(x ^ y for x, y in zip(acc, u))
        out += acc

    return out[:dklen]


# --- TOTP (RFC 6238) -------------------------------------------------------

def generate_totp_secret(nbytes: int = 20) -> str:
    """Generate a random base32 TOTP shared secret (160 bits)."""
    return base64.b32encode(random_bytes(nbytes)).decode()


def _hotp(secret_b32: str, counter: int, digits: int) -> str:
    """HOTP value for a counter (RFC 4226 dynamic truncation)."""
    key = base64.b32decode(secret_b32)
    msg = counter.to_bytes(8, "big")
    h = hmac_sha256(key, msg)
    offset = h[-1] & 0x0F
    code = ((h[offset] & 0x7F) << 24) | (h[offset + 1] << 16) | (h[offset + 2] << 8) | h[offset + 3]
    return str(code % (10 ** digits)).zfill(digits)


def totp_code(secret_b32: str, digits: int = 6, time_step: int = 30, t: int | None = None) -> str:
    """Current TOTP code. ``t`` overrides the Unix time (for tests)."""
    if t is None:
        t = int(time.time())
    return _hotp(secret_b32, t // time_step, digits)


def verify_totp(secret_b32: str, code: str, digits: int = 6, time_step: int = 30,
                window: int = 1, t: int | None = None) -> bool:
    """Verify a TOTP code against the current time, allowing +/- window steps."""
    if t is None:
        t = int(time.time())
    counter = t // time_step
    for w in range(-window, window + 1):
        if constant_time_eq(_hotp(secret_b32, counter + w, digits).encode(), code.encode()):
            return True
    return False