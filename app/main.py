"""PrimeFeed CTI Ledger -- FastAPI application entry point.

Wires together the ciphertext vault (SQLite), the from-scratch crypto engine,
the Key Management Module, and the API routers. On first boot it generates the
ElGamal domain parameters, the server master key, and the server secret, and
bootstraps an administrator account.
"""

import json
import os
import time

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .api import admin, auth, comments, dev, messages, posts, profile, users
from .core import config, database, security
from .crypto import elgamal, key_manager, rsa, totp


class AppContext:
    """Shared application state (db, domain, key manager, secrets)."""

    def __init__(self):
        self.db = database.Database(config.DATABASE_PATH)
        self.domain = elgamal.load_domain(config.DOMAIN_PARAMS_PATH,
                                          p_bits=config.ELGAMAL_P_BITS,
                                          q_bits=config.ELGAMAL_Q_BITS)
        self.secret = security.load_or_create_secret(config.SECRET_PATH)
        self.master_key = security.load_or_create_master_key(config.MASTER_KEY_PATH)
        self.key_manager = key_manager.KeyManager(
            self.db, self.domain,
            self.master_key, self.master_key,
            crypto_period_days=config.CRYPTO_PERIOD_DAYS)
        self.pending_2fa = {}  # ticket -> {user_id, expires} (in-memory, short-lived)


def create_app() -> FastAPI:
    app = FastAPI(title="PrimeFeed CTI Ledger", version="1.0.0")

    # Dev-friendly CORS: the static pages may also be opened standalone or on a
    # separate origin during development.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    ctx = AppContext()
    app.state.ctx = ctx

    app.include_router(auth.router)
    app.include_router(posts.router)
    app.include_router(comments.router)
    app.include_router(users.router)
    app.include_router(messages.router)
    app.include_router(profile.router)
    app.include_router(admin.router)
    app.include_router(dev.router)

    _bootstrap_admin(ctx)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "service": "primefeed"}

    # Serve the frontend (the 4 designed pages) from the same process so a
    # single command runs UI + API on one origin. Mounted LAST so /api/*
    # resolves to the routers above.
    if os.path.isdir(config.FRONTEND_DIR):
        app.mount("/", StaticFiles(directory=config.FRONTEND_DIR, html=True), name="frontend")

    return app


def _bootstrap_admin(ctx: AppContext) -> None:
    """Create the initial administrator on first boot (idempotent)."""
    existing = ctx.db.fetchone("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    if existing:
        return

    username = config.ADMIN_USERNAME
    password = config.ADMIN_PASSWORD
    email = config.ADMIN_EMAIL

    hash_hex, salt_hex = security.hash_password(password)
    totp_secret = totp.generate_totp_secret()

    now = int(time.time())
    with ctx.db.transaction() as cur:
        cur.execute(
            """INSERT INTO users (username, password_hash, salt, totp_secret, role, is_suspended, created_at)
               VALUES (?, ?, ?, ?, 'admin', 0, ?)""",
            (username, hash_hex, salt_hex, totp_secret, now))
        user_id = cur.lastrowid

    pub = ctx.key_manager.generate_user_keys(user_id)

    payload = json.dumps({"email": email, "name": "Platform Administrator", "contact": ""}).encode()
    rsa_pub = rsa.parse_rsa_public(pub["rsa_public"])
    ciphertext = rsa.rsa_encrypt_bytes(rsa_pub, payload).hex()
    badge = security.make_integrity_badge("profile", user_id, ciphertext, ctx.secret)
    ctx.db.execute(
        "INSERT INTO profiles (user_id, encrypted, key_ref, hmac, updated_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, ciphertext, pub["rsa_public"], badge, now))


app = create_app()