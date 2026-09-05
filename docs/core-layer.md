# Core Layer

## config.py

Central configuration, all overridable via environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `PRIMEFEED_DB` | `data/primefeed.db` | SQLite vault path |
| `PRIMEFEED_CRYPTO_PERIOD_DAYS` | `90` | Key crypto period |
| `PRIMEFEED_RSA_BITS` | `3072` | RSA key size |
| `PRIMEFEED_ELGAMAL_P_BITS` | `2048` | ElGamal group modulus size |
| `PRIMEFEED_ELGAMAL_Q_BITS` | `256` | ElGamal subgroup order size |
| `PRIMEFEED_PBKDF2_ITERATIONS` | `10000` | Password KDF cost (pure-Python; 120k would take ~70s/login) |
| `PRIMEFEED_SESSION_TTL` | `86400` | Session lifetime (s) |
| `PRIMEFEED_ADMIN_USERNAME/PASSWORD/EMAIL` | `admin` / `temporary_admin_password` | Bootstrap admin |

## database.py — the ciphertext vault

SQLite acts as a **dumb storage vault**: it holds only ciphertext blobs,
password hashes, HMAC signatures, and non-sensitive metadata. No plaintext
critical data is ever written.

Tables:

| Table | Contents |
|---|---|
| `users` | username, PBKDF2 hash, salt, TOTP secret, role, suspension flag |
| `profiles` | RSA-encrypted profile JSON + HMAC badge |
| `keys` | public keys (clear) + wrapped private keys (ciphertext) + lifecycle |
| `sessions` | hashed session tokens + expiry + client metadata |
| `posts` | ElGamal-encrypted IoC payloads + HMAC badges |
| `messages` | ElGamal-encrypted DMs (recipient copy + sender copy) + HMAC badges |
| `integrity_log` | system-wide HMAC verification failures |

The wrapper is thread-safe (per-connection lock) and supports transactions.

## security.py

- **Passwords**: `hash_password` → PBKDF2-HMAC-SHA256 with a random 16-byte
  salt (nonce); `verify_password` compares in constant time.
- **Sessions**: `generate_session_token` (256 bits of entropy, exceeding the
  ≥ 64-bit requirement), `sign_session_token` (HMAC binds token to user id),
  `verify_session_token` (constant-time). Tokens are stored **hashed** in the
  database, so a DB leak does not expose live sessions.
- **Integrity badges**: `make_integrity_badge(record_type, record_id,
  ciphertext, secret)` → HMAC-SHA256 over the record's ciphertext.
  `verify_integrity_badge` checks in constant time; failures are recorded in
  `integrity_log` for admin review.
- **Server secrets**: `load_or_create_secret` / `load_or_create_master_key`
  persist the session-signing secret and the vault-wrapping master key on
  first boot.