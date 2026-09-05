"""Database layer -- a strict ciphertext vault.

SQLite acts as a dumb storage vault: it holds only ciphertext blobs, password
hashes, HMAC signatures, and non-sensitive metadata. No plaintext critical data
is ever written here.

Schema:
- users: identity + salted password hash + TOTP secret + role + suspension.
- profiles: RSA-encrypted profile fields (email, name, contact).
- keys: public keys in the clear (public directory) + wrapped private keys.
- sessions: HMAC-signed session tokens (token hash stored, not the token).
- posts: ElGamal-encrypted IoC payloads + HMAC integrity badges.
- messages: ElGamal-encrypted direct messages + HMAC integrity badges.
- integrity_log: system-wide HMAC verification failure records (admin view).
"""

import os
import sqlite3
import threading

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,          -- PBKDF2-HMAC-SHA256(salt, password)
    salt          TEXT NOT NULL,          -- random nonce, hex
    totp_secret   TEXT NOT NULL,          -- base32 TOTP shared secret
    role          TEXT NOT NULL DEFAULT 'user',   -- 'user' | 'admin'
    is_suspended  INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS profiles (
    user_id       INTEGER PRIMARY KEY REFERENCES users(id),
    encrypted     TEXT NOT NULL,          -- RSA-3072 ciphertext of profile JSON
    hmac          TEXT NOT NULL,          -- integrity badge over the ciphertext
    key_ref       TEXT,                   -- RSA public key used to encrypt (for rotation-safe decrypt)
    updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id            INTEGER NOT NULL REFERENCES users(id),
    algorithm          TEXT NOT NULL,     -- 'RSA' | 'ELGAMAL'
    public_key         TEXT NOT NULL,     -- public directory entry
    private_key_wrapped TEXT NOT NULL,    -- RSA-wrapped private key (ciphertext)
    status             TEXT NOT NULL DEFAULT 'active',  -- active|deactivated|destroyed
    activated_at       INTEGER NOT NULL,
    expires_at         INTEGER NOT NULL,  -- crypto period end
    deactivated_at     INTEGER,
    destroyed_at       INTEGER,
    created_at         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL,             -- SHA-256 of the session token
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    client_ip  TEXT,
    user_agent TEXT
);

CREATE TABLE IF NOT EXISTS posts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id  INTEGER NOT NULL REFERENCES users(id),
    ciphertext TEXT NOT NULL,             -- ElGamal-encrypted IoC payload
    hmac       TEXT NOT NULL,             -- integrity badge over ciphertext
    key_ref    TEXT,                      -- ElGamal public key used (rotation-safe decrypt)
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id    INTEGER NOT NULL REFERENCES posts(id),
    author_id  INTEGER NOT NULL REFERENCES users(id),
    ciphertext TEXT NOT NULL,             -- ElGamal-encrypted comment
    hmac       TEXT NOT NULL,             -- integrity badge over ciphertext
    key_ref    TEXT,                      -- ElGamal public key used
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id  INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    ciphertext TEXT NOT NULL,             -- ElGamal-encrypted message (recipient key)
    sender_ciphertext TEXT NOT NULL,      -- ElGamal-encrypted copy (sender key, for the sent view)
    hmac       TEXT NOT NULL,             -- integrity badge over both ciphertexts
    key_ref       TEXT,                   -- recipient ElGamal public key used
    sender_key_ref TEXT,                  -- sender ElGamal public key used
    created_at INTEGER NOT NULL,
    read_at    INTEGER
);

CREATE TABLE IF NOT EXISTS integrity_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    record_type TEXT NOT NULL,            -- 'post' | 'message' | 'profile'
    record_id  INTEGER NOT NULL,
    reason     TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_keys_user ON keys(user_id, algorithm, status);
CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id, created_at);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id, created_at);
"""


_MIGRATIONS = [
    "ALTER TABLE posts ADD COLUMN key_ref TEXT",
    "ALTER TABLE comments ADD COLUMN key_ref TEXT",
    "ALTER TABLE profiles ADD COLUMN key_ref TEXT",
    "ALTER TABLE messages ADD COLUMN key_ref TEXT",
    "ALTER TABLE messages ADD COLUMN sender_key_ref TEXT",
]


def _run_migrations(conn) -> None:
    """Add the key_ref columns to databases created before they existed."""
    for sql in _MIGRATIONS:
        try:
            conn.execute(sql)
        except sqlite3.OperationalError:
            pass  # column already exists (or table new) — ignore


class Database:
    """Thin SQLite wrapper with a per-connection lock (thread-safe)."""

    def __init__(self, path: str | None = None):
        self.path = path or config.DATABASE_PATH
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            _run_migrations(self._conn)  # add key_ref columns to pre-existing DBs
            self._conn.commit()

    def execute(self, sql: str, params: tuple = ()) -> int:
        """Run a write statement; returns rowcount."""
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur.rowcount

    def fetchone(self, sql: str, params: tuple = ()):
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def fetchall(self, sql: str, params: tuple = ()) -> list:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def last_insert_id(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def transaction(self):
        """Context manager for multi-statement transactions."""
        return _Transaction(self)

    def close(self):
        with self._lock:
            self._conn.close()


class _Transaction:
    def __init__(self, db: Database):
        self.db = db

    def __enter__(self):
        self.db._lock.acquire()
        self.cur = self.db._conn.cursor()
        return self.cur

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self.db._conn.commit()
            else:
                self.db._conn.rollback()
        finally:
            self.db._lock.release()
        return False