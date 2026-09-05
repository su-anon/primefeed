"""Prime generation, modular arithmetic, and constant-time comparison.

Everything here is built from scratch on Python's native arbitrary-precision
integers. Entropy comes from ``os.urandom`` (the OS kernel CSPRNG) -- Python
itself has no usable math-CSPRNG, and even OpenSSL ultimately reseeds from the
kernel, so this is the correct entropy source rather than a re-implemented PRNG.
"""

import hmac
import secrets


def random_bytes(n: int) -> bytes:
    """Return ``n`` cryptographically secure random bytes."""
    return secrets.token_bytes(n)


def random_int(lo: int, hi: int) -> int:
    """Uniformly random integer in [lo, hi] (inclusive)."""
    return lo + secrets.randbelow(hi - lo + 1)


def random_odd_bits(bits: int) -> int:
    """Random odd integer with exactly ``bits`` bits (top bit and LSB set)."""
    v = secrets.randbits(bits)
    v |= 1 << (bits - 1)
    v |= 1
    return v


def _sieve(limit: int):
    """Simple sieve of Eratosthenes, used to build the small-prime table."""
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = b"\x00" * (((limit - i * i) // i) + 1)
    return [i for i in range(limit + 1) if sieve[i]]


# First 1229 primes (all primes < 10,000) used as a fast trial-division filter
# before the expensive Miller-Rabin rounds.
SMALL_PRIMES = _sieve(10000)


def is_probable_prime(n: int, rounds: int = 24) -> bool:
    """Miller-Rabin primality test with ``rounds`` random bases."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p

    # n - 1 = d * 2^r with d odd
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = random_int(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int, rounds: int = 24) -> int:
    """Generate a probable prime of exactly ``bits`` bits.

    Expected candidates per prime is roughly ln(2^bits) ~= 0.693 * bits; each
    candidate is filtered through trial division before Miller-Rabin.
    """
    while True:
        candidate = random_odd_bits(bits)
        if is_probable_prime(candidate, rounds):
            return candidate


def modinv(a: int, m: int) -> int:
    """Modular inverse of ``a`` modulo ``m`` using Python's built-in pow."""
    try:
        return pow(a, -1, m)
    except ValueError:
        raise ValueError("value is not invertible modulo m")


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time using standard library."""
    return hmac.compare_digest(a, b)