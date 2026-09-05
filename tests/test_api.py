"""End-to-end API tests against a temporary database.

Run:  python -m pytest tests/test_api.py -v
"""

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

# Point the app at a throwaway database BEFORE importing it.
_tmpdir = tempfile.mkdtemp(prefix="primefeed_test_")
os.environ["PRIMEFEED_DB"] = os.path.join(_tmpdir, "test.db")
os.environ["PRIMEFEED_CRYPTO_PERIOD_DAYS"] = "90"
# Small keys + low KDF cost so the suite runs in seconds (production defaults
# are RSA-3072 / ElGamal-2048 / 120k PBKDF2 iterations).
os.environ["PRIMEFEED_RSA_BITS"] = "1024"
os.environ["PRIMEFEED_ELGAMAL_P_BITS"] = "512"
os.environ["PRIMEFEED_ELGAMAL_Q_BITS"] = "128"
os.environ["PRIMEFEED_PBKDF2_ITERATIONS"] = "1000"

from app.main import create_app  # noqa: E402
from app.crypto import totp_code  # noqa: E402


@pytest.fixture(scope="module")
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


def _register(client, username, password="Password123!", email=None):
    r = client.post("/api/auth/register", json={
        "username": username,
        "password": password,
        "email": email or f"{username}@example.com",
        "name": username.title(),
        "contact": "+1-555-0100",
    })
    assert r.status_code == 200, r.text
    return r.json()


def _login(client, username, password="Password123!"):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    ticket = r.json()["ticket"]
    # Fetch the TOTP secret from the DB via the app context.
    ctx = client.app.state.ctx
    row = ctx.db.fetchone("SELECT totp_secret FROM users WHERE username = ?", (username,))
    code = totp_code(row["totp_secret"])
    r2 = client.post("/api/auth/login/2fa", json={"ticket": ticket, "code": code})
    assert r2.status_code == 200, r2.text
    return r2.json()["session_token"]


def _restore_user(client, username):
    """Reset a user to a clean active state (unsuspend, active keys, role user)
    so tests are independent even though they share one module-scoped DB."""
    ctx = client.app.state.ctx
    row = ctx.db.fetchone("SELECT id FROM users WHERE username = ?", (username,))
    if row is None:
        uid = _register(client, username)["user_id"]
    else:
        uid = row["id"]
        ctx.db.execute("UPDATE users SET is_suspended = 0 WHERE id = ?", (uid,))
        if username != "admin":
            ctx.db.execute("UPDATE users SET role = 'user' WHERE id = ?", (uid,))
        ctx.db.execute("DELETE FROM sessions WHERE user_id = ?", (uid,))
        acts = ctx.db.fetchone(
            "SELECT COUNT(*) c FROM keys WHERE user_id = ? AND status = 'active'", (uid,))["c"]
        if acts == 0:
            ctx.key_manager.generate_user_keys(uid)
    return uid


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_register_and_login_flow(client):
    data = _register(client, "alice")
    assert data["ok"] is True
    assert data["totp_secret"]  # 2FA secret returned for enrollment

    # Wrong password rejected
    r = client.post("/api/auth/login", json={"username": "alice", "password": "wrongpass"})
    assert r.status_code == 401

    # Correct password -> 2FA ticket
    r = client.post("/api/auth/login", json={"username": "alice", "password": "Password123!"})
    assert r.status_code == 200
    assert r.json()["requires_2fa"] is True

    # Bad 2FA code rejected
    r = client.post("/api/auth/login/2fa", json={"ticket": r.json()["ticket"], "code": "000000"})
    assert r.status_code == 401

    # Good 2FA code -> session token
    token = _login(client, "alice")
    assert len(token) > 64  # >= 64 bits of entropy in the token portion

    # /me works with the token
    r = client.get("/api/auth/me", headers={"x-session-token": token})
    assert r.status_code == 200
    assert r.json()["username"] == "alice"
    assert r.json()["role"] == "user"


def test_profile_encrypted_roundtrip(client):
    token = _login(client, "alice")
    r = client.get("/api/profile", headers={"x-session-token": token})
    assert r.status_code == 200
    assert r.json()["profile"]["email"] == "alice@example.com"
    assert r.json()["integrity"] == "verified"

    r = client.put("/api/profile", headers={"x-session-token": token},
                   json={"email": "alice@new.example.com", "name": "Alice R.", "contact": ""})
    assert r.status_code == 200
    r = client.get("/api/profile", headers={"x-session-token": token})
    assert r.json()["profile"]["email"] == "alice@new.example.com"


def test_posts_crud_and_integrity(client):
    token = _login(client, "alice")
    r = client.post("/api/posts", headers={"x-session-token": token},
                    json={"content": "IOC: 185.220.101.34 | CVE-2024-1234"})
    assert r.status_code == 200, r.text
    post_id = r.json()["post_id"]

    r = client.get("/api/posts", headers={"x-session-token": token})
    assert r.status_code == 200
    assert r.json()["count"] == 1
    assert r.json()["posts"][0]["content"] == "IOC: 185.220.101.34 | CVE-2024-1234"
    assert r.json()["posts"][0]["integrity"] == "verified"

    # Tamper with the ciphertext in the DB -> integrity failure logged, post hidden
    ctx = client.app.state.ctx
    row = ctx.db.fetchone("SELECT ciphertext FROM posts WHERE id = ?", (post_id,))
    # Flip the first hex nibble (guaranteed to change the ciphertext).
    first = row[0][0]
    flipped = "f" if first != "f" else "e"
    tampered = flipped + row[0][1:]
    ctx.db.execute("UPDATE posts SET ciphertext = ? WHERE id = ?", (tampered, post_id))

    r = client.get("/api/posts", headers={"x-session-token": token})
    assert r.json()["count"] == 0  # tampered post hidden

    log = ctx.db.fetchall("SELECT * FROM integrity_log")
    assert len(log) == 1
    assert log[0]["record_type"] == "post"

    # Admin can review the integrity log
    admin_token = _login(client, "admin", "ChangeMe_Admin_2026!")
    r = client.get("/api/admin/integrity-log", headers={"x-session-token": admin_token})
    assert r.status_code == 200
    assert len(r.json()["entries"]) == 1


def test_messages_end_to_end(client):
    _register(client, "bob")
    alice_token = _login(client, "alice")
    bob_token = _login(client, "bob")

    ctx = client.app.state.ctx
    bob_id = ctx.db.fetchone("SELECT id FROM users WHERE username = 'bob'")["id"]

    r = client.post("/api/messages", headers={"x-session-token": alice_token},
                    json={"recipient_id": bob_id, "content": "CVE-2024-9999 is being exploited"})
    assert r.status_code == 200, r.text

    r = client.get("/api/messages/inbox", headers={"x-session-token": bob_token})
    assert r.status_code == 200
    assert r.json()["count"] == 1
    assert r.json()["messages"][0]["content"] == "CVE-2024-9999 is being exploited"
    assert r.json()["messages"][0]["sender"] == "alice"

    r = client.get("/api/messages/sent", headers={"x-session-token": alice_token})
    assert r.json()["count"] == 1


def test_rbac_admin_only(client):
    alice_token = _login(client, "alice")
    # Regular user cannot access admin endpoints
    r = client.get("/api/admin/users", headers={"x-session-token": alice_token})
    assert r.status_code == 403

    admin_token = _login(client, "admin", "ChangeMe_Admin_2026!")
    r = client.get("/api/admin/users", headers={"x-session-token": admin_token})
    assert r.status_code == 200
    usernames = {u["username"] for u in r.json()["users"]}
    assert {"alice", "bob", "admin"} <= usernames


def test_admin_suspend_and_rotation(client):
    admin_token = _login(client, "admin", "ChangeMe_Admin_2026!")
    ctx = client.app.state.ctx
    bob_id = ctx.db.fetchone("SELECT id FROM users WHERE username = 'bob'")["id"]

    # Suspend bob -> his keys destroyed, sessions revoked
    r = client.post(f"/api/admin/users/{bob_id}/suspend", headers={"x-session-token": admin_token})
    assert r.status_code == 200

    keys = ctx.db.fetchall("SELECT status FROM keys WHERE user_id = ?", (bob_id,))
    assert all(k["status"] == "destroyed" for k in keys)

    # Global rotation
    r = client.post("/api/admin/rotate-keys", headers={"x-session-token": admin_token})
    assert r.status_code == 200
    assert r.json()["rotated_users"] >= 2

    # Key summary shows lifecycle states
    r = client.get("/api/admin/key-summary", headers={"x-session-token": admin_token})
    assert r.status_code == 200
    assert len(r.json()["keys"]) > 0


def test_comments_flow(client):
    _restore_user(client, "alice")
    _restore_user(client, "bob")
    alice_token = _login(client, "alice")
    bob_token = _login(client, "bob")
    ctx = client.app.state.ctx
    ctx.db.execute("DELETE FROM posts")  # keep the test hermetic
    r = client.post("/api/posts", headers={"x-session-token": alice_token},
                    json={"content": "IOC: commentable"})
    post_id = r.json()["post_id"]

    # bob comments on alice's post
    r = client.post(f"/api/posts/{post_id}/comments", headers={"x-session-token": bob_token},
                    json={"content": "Verified indicator, thanks."})
    assert r.status_code == 200, r.text
    cid = r.json()["comment_id"]

    # list decrypts for a viewer
    r = client.get(f"/api/posts/{post_id}/comments", headers={"x-session-token": alice_token})
    assert r.status_code == 200
    assert r.json()["count"] == 1
    assert r.json()["comments"][0]["content"] == "Verified indicator, thanks."
    assert r.json()["comments"][0]["author"] == "bob"

    # non-owner cannot delete
    r = client.delete(f"/api/comments/{cid}", headers={"x-session-token": alice_token})
    assert r.status_code == 403

    # author can delete
    r = client.delete(f"/api/comments/{cid}", headers={"x-session-token": bob_token})
    assert r.status_code == 200
    r = client.get(f"/api/posts/{post_id}/comments", headers={"x-session-token": alice_token})
    assert r.json()["count"] == 0


def test_users_directory(client):
    _restore_user(client, "alice")
    _restore_user(client, "bob")
    token = _login(client, "alice")
    r = client.get("/api/users", headers={"x-session-token": token})
    assert r.status_code == 200
    names = {u["username"] for u in r.json()["users"]}
    assert {"alice", "bob", "admin"} <= names


def test_admin_governance_and_moderation(client):
    _restore_user(client, "bob")
    admin_token = _login(client, "admin", "ChangeMe_Admin_2026!")
    ctx = client.app.state.ctx

    # elevate bob (currently user) to admin
    bob_id = ctx.db.fetchone("SELECT id FROM users WHERE username = 'bob'")["id"]
    r = client.post(f"/api/admin/users/{bob_id}/elevate", headers={"x-session-token": admin_token})
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "admin"

    # reset-2fa and reset-password return new secrets and revoke sessions
    r = client.post(f"/api/admin/users/{bob_id}/reset-2fa", headers={"x-session-token": admin_token})
    assert r.status_code == 200 and len(r.json()["totp_secret"]) > 10
    r = client.post(f"/api/admin/users/{bob_id}/reset-password", headers={"x-session-token": admin_token})
    assert r.status_code == 200 and len(r.json()["temporary_password"]) >= 8

    # moderator can list all posts (decrypted) and delete any post
    alice_token = _login(client, "alice")
    r = client.post("/api/posts", headers={"x-session-token": alice_token},
                    json={"content": "moderated post"})
    pid = r.json()["post_id"]
    r = client.get("/api/admin/posts", headers={"x-session-token": admin_token})
    assert r.status_code == 200
    row = next((p for p in r.json()["posts"] if p["id"] == pid), None)
    assert row and row["content"] == "moderated post" and row["integrity"] == "verified"

    r = client.delete(f"/api/admin/posts/{pid}", headers={"x-session-token": admin_token})
    assert r.status_code == 200
    assert ctx.db.fetchone("SELECT id FROM posts WHERE id = ?", (pid,)) is None


def test_change_password(client):
    token = _login(client, "alice")
    r = client.post("/api/auth/change-password", headers={"x-session-token": token},
                    json={"current_password": "Password123!", "new_password": "BrandNewPass456!"})
    assert r.status_code == 200, r.text
    # old token revoked -> /me fails
    r = client.get("/api/auth/me", headers={"x-session-token": token})
    assert r.status_code == 401
    # new password works
    r = client.post("/api/auth/login", json={"username": "alice", "password": "BrandNewPass456!"})
    assert r.status_code == 200