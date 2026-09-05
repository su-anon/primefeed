# Key Management Module (KMM)

`app/crypto/key_manager.py`

## Responsibilities

1. **Automated key generation** — every user gets an RSA-3072 keypair and an
   ElGamal keypair at registration.
2. **Encrypted vault storage** — private keys are stored **only as
   ciphertext**: each private key string is RSA-encrypted with the server
   master key before it touches the database.
3. **Public key directory** — active public keys are stored in the clear and
   used to encrypt outbound messages and verify signatures.
4. **Lifecycle & rotation** — keys move through `active → deactivated →
   destroyed`, with a **crypto period** (default 90 days) defining how long a
   key stays in active use.
5. **Global rotation** — administrators can trigger a platform-wide rotation
   that deactivates every active key and generates fresh ones.

## The vault

```
users.keys table
├── public_key            (clear text — public directory)
├── private_key_wrapped   (RSA-3072 ciphertext of the private key string)
├── status                active | deactivated | destroyed
├── activated_at / expires_at / deactivated_at / destroyed_at
└── algorithm             RSA | ELGAMAL
```

The server master key lives on the filesystem (`data/master_key.json`), never
in the database. Private keys are unwrapped **in memory only** at the moment
they are needed (decrypt a post, decrypt an inbox) and are never written back
in plaintext.

## Lifecycle

| State | Meaning |
|---|---|
| `active` | In use for encryption/decryption; within its crypto period |
| `deactivated` | Past its crypto period or rotated out; no longer used |
| `destroyed` | Permanently removed (account suspension) |

- `rotate_user_keys(user_id)` — deactivate current, generate fresh.
- `rotate_all_keys()` — global rotation (admin endpoint).
- `destroy_user_keys(user_id)` — used when an account is suspended.
- `expire_overdue_keys()` — scheduled enforcement of the crypto period.

## Crypto period

`expires_at = activated_at + CRYPTO_PERIOD_DAYS × 86400`. A key past its
crypto period is deactivated even without an explicit admin rotation, so key
material is never used beyond its intended lifetime.

## Zero-knowledge boundary

The KMM never exposes private keys to the API layer. Administrators can
trigger rotations and destroy keys, but the design makes it impossible for
them to decrypt user-to-user messages: those are encrypted to the *recipient's*
ElGamal public key, and only the recipient's private key (which the admin
never holds in plaintext) can decrypt them.