# Testing

## Running the suite

```bash
cd Backend
python -m pytest tests/ -v
```

## test_crypto.py — crypto engine

- SHA-256 against the NIST vectors (empty, "abc", 1M × "a").
- HMAC-SHA256 against the RFC 4231 vector.
- PBKDF2-HMAC-SHA256 against the standard vector.
- TOTP self-consistency (valid code passes, wrong code fails, codes change
  across time steps).
- RSA encrypt/decrypt roundtrip + sign/verify (1024-bit key for speed).
- ElGamal roundtrip across single-block, multi-block, and boundary-length
  messages (512-bit group for speed).
- Prime generation sanity (256-bit prime, correct bit length).

## test_api.py — end-to-end flow

Uses a throwaway SQLite database and **small keys** (RSA-1024, ElGamal-512,
PBKDF2-1000) so the suite runs in seconds. Production defaults are
RSA-3072 / ElGamal-2048 / 10k iterations.

Covers:

1. Health check.
2. Register → login → 2FA → session token (wrong password and wrong 2FA code
   rejected; token entropy > 64 bits).
3. Profile RSA roundtrip (read, update, read again).
4. Posts CRUD + **tamper detection**: flipping a hex nibble of the stored
   ciphertext makes the post disappear from the feed and writes an entry to
   `integrity_log`, which the admin can review.
5. Messages end-to-end (alice → bob; bob's inbox and alice's sent view both
   decrypt correctly).
6. RBAC: a regular user gets 403 on admin endpoints; the admin can list users.
7. Admin governance: suspend (keys destroyed, sessions revoked), global
   rotation, key-summary.

## Why small keys in tests?

Pure-Python RSA-3072 key generation takes ~2 minutes per keypair and a 2048-bit
ElGamal domain takes ~1 minute to generate. That is fine for production
one-time costs but would make the test suite unusable. The key sizes are
configurable via environment variables precisely so tests can use small values
while production keeps the full-strength defaults.