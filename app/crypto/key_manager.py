"""Key Management Module (KMM).

Responsibilities:
- Generate RSA-3072 and ElGamal keypairs for every user at registration.
- Store ALL private keys as ciphertext in the database (encrypted with the
  server master key via RSA -- the vault is a "ciphertext-only" store).
- Maintain a public key directory for outbound message encryption and
  signature verification.
- Enforce a key lifecycle: generated -> active -> deactivated -> destroyed,
  with a "crypto period" (how long a key stays in active use) and
  administrator-triggered global rotation.
"""

import json
import time

from ..core import config
from ..crypto import elgamal, rsa
from ..crypto.math_utils import random_bytes


class KeyManager:
    """High-level key lifecycle manager bound to a database connection."""

    def __init__(self, db, domain, master_public_key, master_private_key,
                 crypto_period_days: int = 90):
        self.db = db
        self.domain = domain
        self.master_public = master_public_key
        self.master_private = master_private_key
        self.crypto_period_days = crypto_period_days

    # --- Generation --------------------------------------------------------

    def generate_user_keys(self, user_id: int) -> dict:
        """Generate RSA + ElGamal keypairs for a user and store them in the vault.

        Returns {"rsa_public", "elgamal_public"} for the public directory.
        """
        rsa_key = rsa.generate_rsa_keypair(config.RSA_KEY_BITS)
        elg_key = self.domain.generate_keypair()

        now = int(time.time())
        period = self.crypto_period_days * 86400

        # Private keys are wrapped (encrypted) with the server master key
        # before touching the database.
        rsa_priv_wrapped = rsa.rsa_encrypt_bytes(
            self.master_public, rsa.serialize_rsa_private(rsa_key).encode())
        elg_priv_wrapped = rsa.rsa_encrypt_bytes(
            self.master_public,
            elgamal.serialize_elgamal_private(self.domain, elg_key).encode())

        rsa_pub = rsa.serialize_rsa_public(rsa_key)
        elg_pub = elgamal.serialize_elgamal_public(self.domain, elg_key)

        with self.db.transaction() as cur:
            cur.execute(
                """INSERT INTO keys (user_id, algorithm, public_key, private_key_wrapped,
                                     status, activated_at, expires_at, created_at)
                   VALUES (?, 'RSA', ?, ?, 'active', ?, ?, ?)""",
                (user_id, rsa_pub, rsa_priv_wrapped.hex(), now, now + period, now))
            cur.execute(
                """INSERT INTO keys (user_id, algorithm, public_key, private_key_wrapped,
                                     status, activated_at, expires_at, created_at)
                   VALUES (?, 'ELGAMAL', ?, ?, 'active', ?, ?, ?)""",
                (user_id, elg_pub, elg_priv_wrapped.hex(), now, now + period, now))

        return {"rsa_public": rsa_pub, "elgamal_public": elg_pub}

    # --- Vault access ------------------------------------------------------

    def get_active_private_key(self, user_id: int, algorithm: str) -> dict:
        """Unwrap and return the user's active private key for ``algorithm``.

        The private key is decrypted in memory only; it is never written back
        to the database in plaintext.
        """
        row = self.db.fetchone(
            """SELECT private_key_wrapped FROM keys
               WHERE user_id = ? AND algorithm = ? AND status = 'active'
               ORDER BY created_at DESC LIMIT 1""",
            (user_id, algorithm))
        if row is None:
            raise KeyError(f"no active {algorithm} key for user {user_id}")
        wrapped = bytes.fromhex(row[0])
        plain = rsa.rsa_decrypt_bytes(self.master_private, wrapped).decode()
        if algorithm == "RSA":
            return rsa.parse_rsa_private(plain)
        return elgamal.parse_elgamal_private(plain)

    def get_active_public_key(self, user_id: int, algorithm: str) -> str:
        """Return the user's active public key string (public directory)."""
        row = self.db.fetchone(
            """SELECT public_key FROM keys
               WHERE user_id = ? AND algorithm = ? AND status = 'active'
               ORDER BY created_at DESC LIMIT 1""",
            (user_id, algorithm))
        if row is None:
            raise KeyError(f"no active {algorithm} public key for user {user_id}")
        return row[0]

    def get_public_directory(self) -> list:
        """List all active public keys (user_id, algorithm, public_key)."""
        return self.db.fetchall(
            """SELECT user_id, algorithm, public_key FROM keys
               WHERE status = 'active' ORDER BY user_id, algorithm""")

    # --- Decryption with key-rotation fallback -----------------------------

    def get_private_key_candidates(self, user_id: int, algorithm: str) -> list:
        """Unwrap the user's current AND previous (deactivated) private keys for
        ``algorithm``, newest first. Used so ciphertext written before a key
        rotation stays readable after it (old keys remain in the vault)."""
        rows = self.db.fetchall(
            """SELECT private_key_wrapped FROM keys
               WHERE user_id = ? AND algorithm = ? AND status IN ('active', 'deactivated')
               ORDER BY (status = 'active') DESC, created_at DESC""",
            (user_id, algorithm))
        out = []
        for row in rows:
            try:
                plain = rsa.rsa_decrypt_bytes(self.master_private, bytes.fromhex(row[0])).decode()
            except Exception:
                continue
            try:
                out.append(rsa.parse_rsa_private(plain) if algorithm == "RSA"
                           else elgamal.parse_elgamal_private(plain))
            except Exception:
                continue
        return out

    def decrypt_elgamal_fallback(self, user_id: int, ciphertext_hex: str) -> str:
        """Decrypt ElGamal ciphertext using the newest key that succeeds."""
        for key in self.get_private_key_candidates(user_id, "ELGAMAL"):
            try:
                return self.domain.decrypt(key["x"], bytes.fromhex(ciphertext_hex)).decode()
            except Exception:
                continue
        raise ValueError("ciphertext cannot be decrypted with any candidate key")

    def decrypt_rsa_fallback(self, user_id: int, ciphertext_hex: str) -> str:
        """Decrypt RSA ciphertext using the newest key that succeeds."""
        for key in self.get_private_key_candidates(user_id, "RSA"):
            try:
                return rsa.rsa_decrypt_bytes(key, bytes.fromhex(ciphertext_hex)).decode()
            except Exception:
                continue
        raise ValueError("ciphertext cannot be decrypted with any candidate key")

    def get_private_key_for_public(self, user_id: int, algorithm: str, public_key: str):
        """Unwrap the private key matching a stored public key ref."""
        row = self.db.fetchone(
            "SELECT private_key_wrapped FROM keys WHERE user_id = ? AND algorithm = ? AND public_key = ? LIMIT 1",
            (user_id, algorithm, public_key))
        if row is None:
            return None
        try:
            plain = rsa.rsa_decrypt_bytes(self.master_private, bytes.fromhex(row[0])).decode()
            return rsa.parse_rsa_private(plain) if algorithm == "RSA" else elgamal.parse_elgamal_private(plain)
        except Exception:
            return None

    def decrypt_elgamal(self, user_id: int, ciphertext_hex: str, key_ref: str | None = None) -> str:
        """Decrypt ElGamal using the exact key that wrote the record (key_ref),
        falling back to newest-key attempts only for legacy rows without a ref.

        ElGamal never errors on a wrong key (it returns garbage), so the ref is
        what guarantees correct, rotation-safe decryption."""
        if key_ref:
            key = self.get_private_key_for_public(user_id, "ELGAMAL", key_ref)
            if key:
                try:
                    return self.domain.decrypt(key["x"], bytes.fromhex(ciphertext_hex)).decode()
                except Exception:
                    pass
        return self.decrypt_elgamal_fallback(user_id, ciphertext_hex)

    def decrypt_rsa(self, user_id: int, ciphertext_hex: str, key_ref: str | None = None) -> str:
        """Decrypt RSA using the exact key that wrote the record (key_ref)."""
        if key_ref:
            key = self.get_private_key_for_public(user_id, "RSA", key_ref)
            if key:
                try:
                    return rsa.rsa_decrypt_bytes(key, bytes.fromhex(ciphertext_hex)).decode()
                except Exception:
                    pass
        return self.decrypt_rsa_fallback(user_id, ciphertext_hex)

    # --- Lifecycle ---------------------------------------------------------

    def rotate_user_keys(self, user_id: int) -> None:
        """Rotate a single user's keys: deactivate current, generate fresh ones."""
        with self.db.transaction() as cur:
            cur.execute(
                """UPDATE keys SET status = 'deactivated', deactivated_at = ?
                   WHERE user_id = ? AND status = 'active'""",
                (int(time.time()), user_id))
        self.generate_user_keys(user_id)

    def rotate_all_keys(self) -> int:
        """Global rotation: deactivate every active key, regenerate for all users.

        Returns the number of users rotated. Used by administrators to enforce
        the cryptographic lifecycle.
        """
        users = [r[0] for r in self.db.fetchall("SELECT id FROM users WHERE is_suspended = 0")]
        for uid in users:
            self.rotate_user_keys(uid)
        return len(users)

    def destroy_user_keys(self, user_id: int) -> None:
        """Destroy a user's keys (used when an account is suspended)."""
        with self.db.transaction() as cur:
            cur.execute(
                """UPDATE keys SET status = 'destroyed', destroyed_at = ?
                   WHERE user_id = ? AND status IN ('active', 'deactivated')""",
                (int(time.time()), user_id))

    def expire_overdue_keys(self) -> int:
        """Deactivate keys past their crypto period (expires_at).

        Returns the number of keys deactivated. Called on a schedule to enforce
        the crypto period even without an explicit admin rotation.
        """
        now = int(time.time())
        with self.db.transaction() as cur:
            cur.execute(
                """UPDATE keys SET status = 'deactivated', deactivated_at = ?
                   WHERE status = 'active' AND expires_at < ?""",
                (now, now))
            return cur.rowcount

    def key_status_summary(self) -> list:
        """Count keys per status for the admin dashboard."""
        return self.db.fetchall(
            """SELECT algorithm, status, COUNT(*) FROM keys GROUP BY algorithm, status""")

    def generate_master_keypair(self) -> dict:
        """Generate the server master RSA keypair (used to wrap the vault)."""
        return rsa.generate_rsa_keypair(config.RSA_KEY_BITS)


def generate_master_keypair() -> dict:
    """Module-level helper: generate a fresh server master keypair."""
    return rsa.generate_rsa_keypair(config.RSA_KEY_BITS)


def generate_server_secret() -> str:
    """Generate a random server secret (session signing / integrity badges)."""
    return random_bytes(32).hex()