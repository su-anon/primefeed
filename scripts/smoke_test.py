"""Smoke test against a RUNNING PrimeFeed server.

Verifies the full request flow over real HTTP: health -> login -> 2FA ->
session -> create post -> feed -> delete post -> logout. Uses the TOTP secret
directly from the database (same way tests do). Creates and cleans up a test
post, so it is safe to run repeatedly against your dev database.

Usage:
    python scripts/smoke_test.py                  # http://127.0.0.1:8000, admin
    python scripts/smoke_test.py --base http://localhost:9000 --user bob
"""

import argparse
import json
import os
import sqlite3
import sys
import time

import httpx

# Make `app` importable regardless of where the script is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = "http://127.0.0.1:8000"
DB_PATH = None  # resolved relative to this file


def _resolve_db_path() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "data", "primefeed.db")


def totp_code(secret: str) -> str:
    from app.crypto.sha256_hmac import totp_code as _code
    return _code(secret)


def step(name: str, ok: bool, extra: str = ""):
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name} {extra}".rstrip())


def main():
    global DB_PATH
    parser = argparse.ArgumentParser(description="PrimeFeed HTTP smoke test")
    parser.add_argument("--base", default=BASE, help="base URL of the running server")
    parser.add_argument("--user", default="admin", help="username to log in as")
    parser.add_argument("--password", default="temporary_admin_password",
                        help="password (default is the bootstrap admin password)")
    parser.add_argument("--db", default=None, help="path to primefeed.db (for the TOTP secret)")
    args = parser.parse_args()

    DB_PATH = args.db or _resolve_db_path()
    client = httpx.Client(base_url=args.base, timeout=60)
    failures = 0

    def check(name, cond, extra=""):
        nonlocal failures
        step(name, bool(cond), extra)
        if not cond:
            failures += 1

    # 1. Health
    r = client.get("/api/health")
    check("health", r.status_code == 200 and r.json().get("status") == "ok", f"({r.status_code})")

    # 2. Login (step 1: credentials -> 2FA ticket)
    r = client.post("/api/auth/login", json={"username": args.user, "password": args.password})
    check("login (credentials)", r.status_code == 200, f"({r.status_code})")
    if r.status_code != 200:
        print("Stopping: login failed. Is the server running? Did you use the right password?")
        sys.exit(1)
    ticket = r.json()["ticket"]

    # 3. Compute TOTP from the DB and complete step 2
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT totp_secret FROM users WHERE username = ?",
                       (args.user,)).fetchone()
    conn.close()
    if row is None:
        print(f"Stopping: no user '{args.user}' in {DB_PATH}")
        sys.exit(1)
    code = totp_code(row[0])
    r = client.post("/api/auth/login/2fa", json={"ticket": ticket, "code": code})
    check("2fa (TOTP)", r.status_code == 200, f"({r.status_code})")
    if r.status_code != 200:
        print("Stopping: 2FA failed.")
        sys.exit(1)
    token = r.json()["session_token"]
    headers = {"x-session-token": token}

    # 4. /me
    r = client.get("/api/auth/me", headers=headers)
    check("session /me", r.status_code == 200 and r.json()["username"] == args.user,
          f"({r.status_code})")

    # 5. Create a post (ElGamal-encrypted at rest)
    content = f"SMOKE-TEST {int(time.time())}: IOC 203.0.113.7 | CVE-2026-0000"
    r = client.post("/api/posts", headers=headers, json={"content": content})
    check("create post", r.status_code == 200, f"({r.status_code})")
    post_id = r.json().get("post_id")

    # 6. Feed (decrypted on the backend)
    r = client.get("/api/posts", headers=headers)
    check("feed lists post", r.status_code == 200
          and any(p["id"] == post_id and p["content"] == content for p in r.json()["posts"]),
          f"({r.status_code})")

    # 7. Integrity: tampered record must be hidden + logged
    conn = sqlite3.connect(DB_PATH)
    ct = conn.execute("SELECT ciphertext FROM posts WHERE id = ?", (post_id,)).fetchone()[0]
    flipped = "f" if ct[0] != "f" else "e"
    conn.execute("UPDATE posts SET ciphertext = ? WHERE id = ?", (flipped + ct[1:], post_id))
    conn.commit()
    conn.close()
    r = client.get("/api/posts", headers=headers)
    check("tamper detection hides post", all(p["id"] != post_id for p in r.json()["posts"]))

    # 8. Cleanup: delete our test post (author-only works for admin)
    r = client.delete(f"/api/posts/{post_id}", headers=headers)
    check("delete test post", r.status_code == 200, f"({r.status_code})")

    # 9. Logout
    r = client.post("/api/auth/logout", json={"session_token": token})
    check("logout", r.status_code == 200, f"({r.status_code})")

    print("-" * 50)
    if failures:
        print(f"SMOKE TEST FAILED: {failures} checks did not pass.")
        sys.exit(1)
    print(f"SMOKE TEST PASSED: all checks ok against {args.base}.")


if __name__ == "__main__":
    main()