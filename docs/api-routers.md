# API Routers & RBAC

## auth.py — Authentication & Identity

- **`POST /api/auth/register`** — validates input, checks username uniqueness,
  hashes the password (PBKDF2 + random salt), generates a TOTP secret, creates
  the user, then:
  1. KMM generates RSA-3072 + ElGamal keypairs (private keys wrapped).
  2. The profile (email, name, contact) is **RSA-encrypted** with the user's
     public key and stored with an HMAC badge.
  Returns the TOTP secret for enrollment.
- **`POST /api/auth/login`** — verifies the salted hash; on success issues a
  short-lived (5 min) in-memory 2FA ticket. Suspended accounts are rejected.
- **`POST /api/auth/login/2fa`** — verifies the TOTP code (mandatory second
  factor), then issues an HMAC-signed session token. The token is stored
  hashed; the raw token is returned once.
- **`POST /api/auth/logout`** — revokes the session.
- **`GET /api/auth/me`** — current user id/role.

## posts.py — Threat Intelligence Feed (CRUD)

- **`GET /api/posts`** — for an authenticated session, fetches the ElGamal
  ciphertexts, verifies each HMAC badge, decrypts in memory, and returns the
  plaintext IoCs. Tampered records are **hidden** and logged to
  `integrity_log`.
- **`POST /api/posts`** — encrypts the IoC payload with the author's ElGamal
  public key, badges it, stores it. Length capped at 500 chars.
- **`GET/PUT/DELETE /api/posts/{id}`** — single post; edit/delete are
  author-only (RBAC check against `author_id`).

## messages.py — Secure Direct Messaging

- **`POST /api/messages`** — encrypts the message with the **recipient's**
  ElGamal public key (end-to-end: only the recipient can decrypt). A second
  copy is encrypted to the **sender's** own key so the "sent" view works. The
  HMAC badge covers both ciphertexts, binding sender identity + payload.
- **`GET /api/messages/inbox`** — decrypts the recipient's copy with the
  caller's private key; integrity-checked.
- **`GET /api/messages/sent`** — decrypts the sender's copy.
- **`POST /api/messages/{id}/read`** — recipient-only read receipt.

## profile.py — Encrypted Personal Profile

- **`GET /api/profile`** — decrypts the caller's RSA-encrypted profile.
- **`PUT /api/profile`** — re-encrypts with the caller's active RSA public key
  and re-badges. Users can only touch their own profile.

## admin.py — Role-Based Access Control

All admin endpoints require `role == 'admin'` (403 otherwise).

- **`GET /api/admin/users`** — list users.
- **`POST /api/admin/users/{id}/suspend`** — suspend a compromised account,
  **destroy its keys**, revoke its sessions. Admins cannot be suspended.
- **`POST /api/admin/users/{id}/restore`** — restore.
- **`POST /api/admin/rotate-keys`** — global key rotation (crypto period
  enforcement).
- **`GET /api/admin/integrity-log`** — review system-wide HMAC failures.
- **`GET /api/admin/key-summary`** — key lifecycle counts.

## RBAC matrix

| Action | Regular user | Admin |
|---|---|---|
| Publish/edit/delete own posts | ✅ | ✅ |
| Manage own DMs | ✅ | ✅ |
| Update own encrypted profile | ✅ | ✅ |
| Suspend accounts | ❌ | ✅ |
| Global key rotation | ❌ | ✅ |
| Review integrity log | ❌ | ✅ |
| Decrypt other users' DMs | ❌ | ❌ (impossible by design) |

## main.py — application wiring

`create_app()` builds the `AppContext` (database, ElGamal domain, server
secret, master key, KMM, in-memory 2FA ticket store), includes all routers,
and bootstraps the initial admin account on first boot. `run.py` launches
uvicorn.