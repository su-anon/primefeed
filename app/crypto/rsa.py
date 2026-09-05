"""From-scratch RSA (3072-bit default) with PKCS#1 v1.5 padding.

- Key generation: two random 1536-bit primes -> 3072-bit modulus n, e = 65537,
  d = e^-1 mod phi(n). Provides ~128 bits of security strength.
- Encrypt/decrypt: textbook RSA with PKCS#1 v1.5 type-2 padding (random padding
  makes the scheme probabilistic). Long payloads are split into blocks.
- Sign/verify: PKCS#1 v1.5 type-1 encoding of a SHA-256 DigestInfo, used to
  verify client requests against the public key directory.
- RSA is used EXCLUSIVELY for user profile data and the private-key vault.
"""

import json

from .math_utils import constant_time_eq, generate_prime, modinv, random_int
from .sha256_hmac import sha256

# DER-encoded DigestInfo prefix for SHA-256 (OID 2.16.840.1.101.3.4.2.1).
_DIGESTINFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


def generate_rsa_keypair(bits: int = 3072, e: int = 65537) -> dict:
    """Generate an RSA keypair as {"n", "e", "d", "p", "q", "bits"}."""
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:  # e must be coprime with phi(n)
            continue
        d = modinv(e, phi)
        return {"n": n, "e": e, "d": d, "p": p, "q": q, "bits": n.bit_length()}


def modulus_bytes(n: int) -> int:
    """Number of bytes in the modulus (octet length k)."""
    return (n.bit_length() + 7) // 8


def rsa_encrypt_bytes(public_key: dict, plaintext: bytes, block_size: int = 300) -> bytes:
    """Encrypt ``plaintext`` with the RSA public key (PKCS#1 v1.5 type 2).

    Each block is encoded as 0x00 || 0x02 || PS || 0x00 || M where PS is at
    least 8 random nonzero bytes, then raised to e mod n.
    """
    n, e = public_key["n"], public_key["e"]
    k = modulus_bytes(n)
    if block_size > k - 11:  # PKCS#1 v1.5 requires >= 8 bytes of padding
        block_size = k - 11

    out = b""
    for i in range(0, len(plaintext), block_size):
        chunk = plaintext[i:i + block_size]
        ps_len = k - len(chunk) - 3
        ps = bytes(random_int(1, 255) for _ in range(ps_len))
        em = b"\x00\x02" + ps + b"\x00" + chunk
        m = int.from_bytes(em, "big")
        c = pow(m, e, n)
        out += c.to_bytes(k, "big")
    return out


def rsa_decrypt_bytes(private_key: dict, ciphertext: bytes) -> bytes:
    """Decrypt a PKCS#1 v1.5 RSA ciphertext with the private key.

    Raises ValueError on malformed ciphertext or wrong key (padding check).
    """
    n, d = private_key["n"], private_key["d"]
    k = modulus_bytes(n)
    if len(ciphertext) == 0 or len(ciphertext) % k != 0:
        raise ValueError("malformed ciphertext length")

    out = b""
    for i in range(0, len(ciphertext), k):
        c = int.from_bytes(ciphertext[i:i + k], "big")
        if c >= n:
            raise ValueError("ciphertext block out of range")
        m = pow(c, d, n)
        em = m.to_bytes(k, "big")
        if em[0] != 0x00 or em[1] != 0x02:
            raise ValueError("invalid padding header")
        sep = em.index(0x00, 2)
        out += em[sep + 1:]
    return out


def rsa_sign(private_key: dict, data: bytes) -> bytes:
    """Sign ``data`` with the private key (PKCS#1 v1.5 type 1, SHA-256)."""
    n, d = private_key["n"], private_key["d"]
    k = modulus_bytes(n)
    t = _DIGESTINFO_SHA256 + sha256(data)
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    m = int.from_bytes(em, "big")
    s = pow(m, d, n)
    return s.to_bytes(k, "big")


def rsa_verify(public_key: dict, data: bytes, signature: bytes) -> bool:
    """Verify an RSA signature against the public key (constant-time compare)."""
    n, e = public_key["n"], public_key["e"]
    k = modulus_bytes(n)
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    m = pow(s, e, n)
    em = m.to_bytes(k, "big")
    t = _DIGESTINFO_SHA256 + sha256(data)
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return constant_time_eq(em, expected)


# --- Serialization ---------------------------------------------------------
# Format: RSA3072.PUBLIC.<n_hex>.<e_hex>  /  RSA3072.PRIVATE.<n_hex>.<d_hex>

def serialize_rsa_public(key: dict) -> str:
    return f"RSA3072.PUBLIC.{key['n']:x}.{key['e']:x}"


def serialize_rsa_private(key: dict) -> str:
    return f"RSA3072.PRIVATE.{key['n']:x}.{key['d']:x}"


def parse_rsa_public(s: str) -> dict:
    parts = s.split(".")
    if len(parts) != 4 or parts[0] != "RSA3072" or parts[1] != "PUBLIC":
        raise ValueError("invalid RSA public key string")
    return {"n": int(parts[2], 16), "e": int(parts[3], 16)}


def parse_rsa_private(s: str) -> dict:
    parts = s.split(".")
    if len(parts) != 4 or parts[0] != "RSA3072" or parts[1] != "PRIVATE":
        raise ValueError("invalid RSA private key string")
    return {"n": int(parts[2], 16), "d": int(parts[3], 16)}


def private_key_to_json(key: dict) -> str:
    """Full private key as JSON (used by the vault wrapper)."""
    return json.dumps(key)