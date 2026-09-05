"""Seed demo users into the running database, then print their TOTP secrets.

Uses the backend's own crypto services directly (registration path with key
generation), so the seeded users are identical to ones created via the UI.
It intentionally does NOT use the network — it writes to the DB on disk, so it
must be run with the same env (key sizes) you use for the server.

Recommended: run before `./dev.sh` and reuse the same env:
    . <(grep '^export PRIMEFEED_' dev.sh)   # load dev key sizes
    python3 scripts/seed_demo_users.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import database, security  # noqa: E402
from app.core import config  # noqa: E402


def seed():
    db = database.Database(config.DATABASE_PATH)
    existing = {r["username"] for r in db.fetchall("SELECT username FROM users")}
    created = []

    demo = [
        # (username, password, email)
        ("emmalin", "IoCPublisher-2026!", "emma.lin@proton.me"),
        ("malikr", "ThreatHunter-2026!", "malik.r@tutanota.com"),
    ]
    for username, password, email in demo:
        if username in existing:
            print(f"[skip] {username} already exists")
            continue

        hash_hex, salt_hex = security.hash_password(password)
        from app.crypto import totp
        totp_secret = totp.generate_totp_secret()

        now = int(time.time())
        with db.transaction() as cur:
            cur.execute(
                """INSERT INTO users (username, password_hash, salt, totp_secret, role, is_suspended, created_at)
                   VALUES (?, ?, ?, ?, 'user', 0, ?)""",
                (username, hash_hex, salt_hex, totp_secret, now))
            user_id = cur.lastrowid

        km = _make_key_manager(db)
        pub = km.generate_user_keys(user_id)

        from app.crypto import rsa
        import json as _json
        payload = _json.dumps({"email": email, "name": username.capitalize(), "contact": ""}).encode()
        rsa_pub = rsa.parse_rsa_public(pub["rsa_public"])
        ciphertext = rsa.rsa_encrypt_bytes(rsa_pub, payload).hex()
        badge = security.make_integrity_badge("profile", user_id, ciphertext, security.load_or_create_secret(config.SECRET_PATH))
        db.execute(
            "INSERT INTO profiles (user_id, encrypted, key_ref, hmac, updated_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, ciphertext, pub["rsa_public"], badge, now))

        created.append((username, password, email, totp_secret))

        # A couple of seed posts so the feed is not empty.
        from app.crypto import elgamal
        from app.crypto.elgamal import load_domain
        domain = load_domain(config.DOMAIN_PARAMS_PATH,
                             p_bits=config.ELGAMAL_P_BITS, q_bits=config.ELGAMAL_Q_BITS)
        elg_pub = km.get_active_public_key(user_id, "ELGAMAL")
        elg_k = elgamal.parse_elgamal_public(elg_pub)
        d2 = elgamal.ElGamalDomain(elg_k["p"], elg_k["q"], elg_k["g"])
        for content in (_seed_posts(username)):
            ct = d2.encrypt(elg_k["y"], content.encode()).hex()
            db.execute(
                "INSERT INTO posts (author_id, ciphertext, key_ref, hmac, created_at, updated_at) VALUES (?, ?, ?, '', ?, ?)",
                (user_id, ct, elg_pub, now, now))
            pid = db.last_insert_id()
            badge = security.make_integrity_badge("post", pid, ct, security.load_or_create_secret(config.SECRET_PATH))
            db.execute("UPDATE posts SET hmac = ? WHERE id = ?", (badge, pid))

    print("-" * 60)
    print("Demo users ready — sign in, then use the DEV auto-fill TOTP button.")
    print("-" * 60)
    for u, pw, email, secret in created:
        print(f"\n  username : {u}\n  password : {pw}\n  email    : {email}")
        print(f"  TOTP     : {secret}   (auto-fill already remembers this)")
    if not created:
        print("\nNothing new created (all demo users already exist).")
    print("-" * 60)
    print(f"DB: {config.DATABASE_PATH}")


def _make_key_manager(db):
    from app.crypto import key_manager, elgamal
    km = key_manager.KeyManager(
        db,
        elgamal.load_domain(config.DOMAIN_PARAMS_PATH,
                            p_bits=config.ELGAMAL_P_BITS, q_bits=config.ELGAMAL_Q_BITS),
        security.load_or_create_master_key(config.MASTER_KEY_PATH),
        security.load_or_create_master_key(config.MASTER_KEY_PATH),
        crypto_period_days=config.CRYPTO_PERIOD_DAYS)
    return km


def _seed_posts(username: str) -> list:
    return [
        f"RESEARCH NOTE by @{username}: 'Avoid reusing ephemeral ElGamal nonces — correlated c1 values leak the plaintext ratio.'",
        f"RESEARCH NOTE by @{username}: 'Verify HMAC badges before trusting any feed row. A single flipped nibble quarantines the record.'",
    ]


if __name__ == "__main__":
    seed()