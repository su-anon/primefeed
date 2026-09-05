"""From-scratch RSA (3072-bit default) with PKCS#1 v1.5 padding.

- Key generation: two random 1536-bit primes -> 3072-bit modulus n, e = 65537,
  d = e^-1 mod phi(n). Provides ~128 bits of security strength.
- Encrypt/decrypt: textbook RSA with PKCS#1 v1.5 type-2 padding (random padding
  makes the scheme probabilistic). Long payloads are split into blocks.
- Sign/verify: PKCS#1 v1.5 type-1 encoding of a SHA-256 DigestInfo, used to
  verify client requests against the public key directory.
- RSA is used EXCLUSIVELY for user profile data and the private-key vault.
"""

import hashlib
import hmac
import json
import os
import secrets

# --- Standalone Primitives & Math Helpers ----------------------------------

_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
    613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
    709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
    821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
    919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997
]


def random_int(lo, hi):
    """Uniformly random integer in [lo, hi] (inclusive) via secrets."""
    span = hi - lo + 1
    return lo + secrets.randbelow(span)


def is_probable_prime(n, rounds=24):
    """Miller-Rabin primality test with small-prime pre-filter."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p

    # Factor n - 1 into odd_component * 2^(power_of_two)
    odd_component = n - 1
    power_of_two = 0
    while odd_component % 2 == 0:
        odd_component //= 2
        power_of_two += 1

    for _ in range(rounds):
        random_base = random_int(2, n - 2)
        test_value = pow(random_base, odd_component, n)

        if test_value in (1, n - 1):
            continue

        for _ in range(power_of_two - 1):
            test_value = pow(test_value, 2, n)
            if test_value == n - 1:
                break

        if test_value != n - 1:
            return False

    return True


def generate_prime(bits, rounds=24):
    """Generate a probable prime of exactly ``bits`` bits from scratch."""
    min_val = 2 ** (bits - 1)
    max_val = (2 ** bits) - 1

    while True:
        candidate = random_int(min_val, max_val)
        if candidate % 2 == 0:
            candidate += 1

        if candidate <= max_val and is_probable_prime(candidate, rounds):
            return candidate


def modinv(a, m):
    """Modular inverse of ``a`` modulo ``m``."""
    return pow(a, -1, m)


def constant_time_eq(a, b):
    """Compare two byte sequences in constant time."""
    return hmac.compare_digest(a, b)


def sha256(data):
    """Return 32-byte SHA-256 digest of data."""
    return hashlib.sha256(data).digest()


# DER-encoded DigestInfo prefix for SHA-256 (OID 2.16.840.1.101.3.4.2.1).
_DIGESTINFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")



def generate_rsa_keypair(bits=3072, e=65537):
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


def modulus_bytes(n):
    """Number of bytes in the modulus (octet length k)."""
    return (n.bit_length() + 7) // 8


def rsa_encrypt_bytes(public_key, plaintext, block_size=300):
    """Encrypt plaintext with the RSA public key (PKCS#1 v1.5 type 2)."""
    n, e = public_key["n"], public_key["e"]
    modulus_length = modulus_bytes(n)

    # PKCS#1 v1.5 requires at least 8 bytes of padding + 3 header bytes
    max_payload = modulus_length - 11
    if block_size > max_payload:
        block_size = max_payload

    ciphertext = b""
    for start_idx in range(0, len(plaintext), block_size):
        chunk = plaintext[start_idx : start_idx + block_size]

        # PKCS#1 v1.5 type 2: 0x00 || 0x02 || random_nonzero_bytes || 0x00 || chunk
        padding_length = modulus_length - len(chunk) - 3
        padding_string = bytes(random_int(1, 255) for _ in range(padding_length))
        encoded_message = b"\x00\x02" + padding_string + b"\x00" + chunk

        message_int = int.from_bytes(encoded_message, "big")
        cipher_int = pow(message_int, e, n)
        ciphertext += cipher_int.to_bytes(modulus_length, "big")

    return ciphertext


def rsa_decrypt_bytes(private_key, ciphertext):
    """Decrypt a PKCS#1 v1.5 RSA ciphertext with the private key."""
    n, d = private_key["n"], private_key["d"]
    modulus_length = modulus_bytes(n)

    if len(ciphertext) == 0 or len(ciphertext) % modulus_length != 0:
        raise ValueError("malformed ciphertext length")

    plaintext = b""
    for start_idx in range(0, len(ciphertext), modulus_length):
        cipher_bytes = ciphertext[start_idx : start_idx + modulus_length]
        cipher_int = int.from_bytes(cipher_bytes, "big")

        if cipher_int >= n:
            raise ValueError("ciphertext block out of range")

        message_int = pow(cipher_int, d, n)
        encoded_message = message_int.to_bytes(modulus_length, "big")

        # Verify PKCS#1 v1.5 type-2 header: 0x00 0x02
        if encoded_message[0] != 0x00 or encoded_message[1] != 0x02:
            raise ValueError("invalid padding header")

        # Find 0x00 delimiter separating random padding from payload
        separator_idx = encoded_message.index(0x00, 2)
        plaintext += encoded_message[separator_idx + 1 :]

    return plaintext


def rsa_sign(private_key, data):
    """Sign data with the private key (PKCS#1 v1.5 type 1, SHA-256)."""
    n, d = private_key["n"], private_key["d"]
    modulus_length = modulus_bytes(n)

    # DigestInfo prefix + SHA-256 hash of data
    digest_info = _DIGESTINFO_SHA256 + sha256(data)
    padding_length = modulus_length - len(digest_info) - 3

    # PKCS#1 v1.5 type 1 uses 0xFF bytes for padding
    encoded_message = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info

    message_int = int.from_bytes(encoded_message, "big")
    signature_int = pow(message_int, d, n)
    return signature_int.to_bytes(modulus_length, "big")


def rsa_verify(public_key, data, signature):
    """Verify an RSA signature against the public key (constant-time compare)."""
    n, e = public_key["n"], public_key["e"]
    modulus_length = modulus_bytes(n)

    if len(signature) != modulus_length:
        return False

    signature_int = int.from_bytes(signature, "big")
    if signature_int >= n:
        return False

    message_int = pow(signature_int, e, n)
    encoded_message = message_int.to_bytes(modulus_length, "big")

    digest_info = _DIGESTINFO_SHA256 + sha256(data)
    padding_length = modulus_length - len(digest_info) - 3
    expected_encoded_message = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info

    return constant_time_eq(encoded_message, expected_encoded_message)


# --- Serialization ---------------------------------------------------------
# Format: RSA3072.PUBLIC.<n_hex>.<e_hex>  /  RSA3072.PRIVATE.<n_hex>.<d_hex>

def serialize_rsa_public(key):
    return f"RSA3072.PUBLIC.{key['n']:x}.{key['e']:x}"


def serialize_rsa_private(key):
    return f"RSA3072.PRIVATE.{key['n']:x}.{key['d']:x}"


def parse_rsa_public(s):
    parts = s.split(".")
    if len(parts) != 4 or parts[0] != "RSA3072" or parts[1] != "PUBLIC":
        raise ValueError("invalid RSA public key string")
    return {"n": int(parts[2], 16), "e": int(parts[3], 16)}


def parse_rsa_private(s):
    parts = s.split(".")
    if len(parts) != 4 or parts[0] != "RSA3072" or parts[1] != "PRIVATE":
        raise ValueError("invalid RSA private key string")
    return {"n": int(parts[2], 16), "d": int(parts[3], 16)}


def private_key_to_json(key):
    """Full private key as JSON (used by the vault wrapper)."""
    return json.dumps(key)
