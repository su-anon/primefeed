# PrimeFeed — Cyber-Threat Intelligence (CTI) Ledger

A highly secure, role-based bulletin board where cybersecurity researchers
publish and share short Indicators of Compromise (IoCs) — malicious IPs, CVE
IDs, malware hashes — with **from-scratch pure-Python asymmetric encryption
algorithms** (RSA-3072 and ElGamal-2048) in accordance with CSE447 project
specifications. Standard modules (`hashlib`, `hmac`, `secrets`, `pyotp`) are
used for non-encryption hashing, MACs, and 2FA.

## Why asymmetric-only?

The platform is strictly constrained to computationally heavy asymmetric
encryption for **all** data storage. Restricting the platform to lightweight
CTI payloads (≤ 500 chars) keeps every encryption/decryption fast and
mathematically viable in pure Python.

## Architecture

```
Browser (HTMX + Jinja2, later)
        │  HTTP
        ▼
FastAPI (app/main.py)
 ├── app/api/        HTTP routers + RBAC enforcement
 │    ├── auth.py        registration, 2FA login, sessions
 │    ├── posts.py       IoC feed CRUD (ElGamal)
 │    ├── messages.py    direct messages (ElGamal, end-to-end)
 │    ├── profile.py     RSA-encrypted personal profiles
 │    └── admin.py       governance: suspend, rotate, integrity log
 ├── app/core/       config, database vault, security layer
 │    ├── config.py      settings (key sizes, crypto period, TTLs)
 │    ├── database.py    SQLite ciphertext vault (schema)
 │    └── security.py    passwords, sessions, integrity badges
 ├── app/crypto/     the from-scratch crypto engine
 │    ├── math_utils.py  primes, modular arithmetic, constant-time compare
 │    ├── sha256_hmac.py SHA-256, HMAC, PBKDF2, TOTP
 │    ├── rsa.py         RSA-3072 (PKCS#1 v1.5) + serialization
 │    ├── elgamal.py     ElGamal over a 2048-bit Schnorr group
 │    ├── totp.py        TOTP re-export
 │    └── key_manager.py Key Management Module (KMM)
 └── run.py          dev launcher
```

## Quick start

```bash
cd Backend
pip install -r requirements.txt
python run.py                 # http://127.0.0.1:8000
```

On first boot the app generates:
- the ElGamal domain parameters (`data/elgamal_domain.json`),
- the server master RSA key (`data/master_key.json`),
- the server secret (`data/server_secret.txt`),
- a bootstrap **admin** account (`admin` / `ChangeMe_Admin_2026!` — change it!).

## Security model

| Concern | Mechanism |
|---|---|
| Profile data | RSA-3072 encryption (PKCS#1 v1.5) |
| Posts & messages | ElGamal encryption (2048-bit Schnorr group) |
| Passwords | PBKDF2-HMAC-SHA256, 10k iterations (pure-Python cost), random 16-byte salt |
| 2FA | Mandatory TOTP (HMAC-SHA256, RFC 6238) |
| Sessions | HMAC-signed tokens, ≥ 64 bits entropy, stored hashed |
| Integrity | HMAC-SHA256 badges over every record's ciphertext |
| Private keys | Stored only as RSA-wrapped ciphertext (vault) |
| Symmetric crypto | **Prohibited** — no AES/DES anywhere |

## API surface

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/register` | — | Register (RSA-encrypted profile, key generation) |
| POST | `/api/auth/login` | — | Step 1: credentials → 2FA ticket |
| POST | `/api/auth/login/2fa` | ticket | Step 2: TOTP → session token |
| POST | `/api/auth/logout` | token | Revoke session |
| GET | `/api/auth/me` | token | Current user |
| GET/POST | `/api/posts` | token | List (decrypted) / create feed posts |
| GET/PUT/DELETE | `/api/posts/{id}` | token | Single post (author-only edit/delete) |
| POST | `/api/messages` | token | Send DM (encrypted to recipient) |
| GET | `/api/messages/inbox` | token | Inbox (decrypted) |
| GET | `/api/messages/sent` | token | Sent (decrypted) |
| POST | `/api/messages/{id}/read` | token | Mark read |
| GET/PUT | `/api/profile` | token | Read/update own RSA-encrypted profile |
| GET | `/api/admin/users` | admin | List users |
| POST | `/api/admin/users/{id}/suspend` | admin | Suspend + destroy keys |
| POST | `/api/admin/users/{id}/restore` | admin | Restore |
| POST | `/api/admin/rotate-keys` | admin | Global key rotation |
| GET | `/api/admin/integrity-log` | admin | HMAC failure log |
| GET | `/api/admin/key-summary` | admin | Key lifecycle counts |
| GET | `/api/health` | — | Health check |

## Testing

```bash
python -m pytest tests/ -v
```

The suite covers known SHA-256/HMAC/PBKDF2 vectors, RSA and ElGamal
roundtrips, and a full end-to-end API flow (register → 2FA → posts → messages
→ tamper detection → admin governance). Tests use small keys for speed;
production defaults are RSA-3072 / ElGamal-2048.

## Documentation

See [`docs/`](docs/) for a module-by-module explanation of the entire backend.

## Roadmap

- Jinja2 + HTMX frontend (templates injected with decrypted payloads)
- PostgreSQL backend (drop-in: the vault schema is portable)
- Scheduled crypto-period enforcement (expire overdue keys)