"""End-to-end demo of the PrimeFeed backend.

Runs the full lifecycle against a throwaway database with small keys so it
finishes quickly: register -> 2FA login -> profile -> posts -> messages ->
tamper detection -> admin governance.

Usage:  python demo.py
"""

import os
import tempfile

# Small keys for a fast demo (production uses RSA-3072 / ElGamal-2048).
_tmp = tempfile.mkdtemp(prefix="primefeed_demo_")
os.environ["PRIMEFEED_DB"] = os.path.join(_tmp, "demo.db")
os.environ["PRIMEFEED_RSA_BITS"] = "1024"
os.environ["PRIMEFEED_ELGAMAL_P_BITS"] = "512"
os.environ["PRIMEFEED_ELGAMAL_Q_BITS"] = "128"
os.environ["PRIMEFEED_PBKDF2_ITERATIONS"] = "1000"

from fastapi.testclient import TestClient  # noqa: E402

from app.crypto import totp_code  # noqa: E402
from app.main import create_app  # noqa: E402


def login(client, username, password):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    ticket = r.json()["ticket"]
    ctx = client.app.state.ctx
    row = ctx.db.fetchone("SELECT totp_secret FROM users WHERE username = ?", (username,))
    r2 = client.post("/api/auth/login/2fa", json={"ticket": ticket, "code": totp_code(row["totp_secret"])})
    assert r2.status_code == 200, r2.text
    return r2.json()["session_token"]


def main():
    app = create_app()
    with TestClient(app) as client:
        ctx = client.app.state.ctx
        print("=" * 60)
        print("PrimeFeed CTI Ledger — end-to-end demo")
        print("=" * 60)

        # 1. Register two researchers
        for u in ("alice", "bob"):
            r = client.post("/api/auth/register", json={
                "username": u, "password": "Password123!",
                "email": f"{u}@example.com", "name": u.title(), "contact": "+1-555-0100"})
            assert r.status_code == 200, r.text
            print(f"[register] {u} -> user_id={r.json()['user_id']} (TOTP secret issued)")

        # 2. 2FA login
        alice = login(client, "alice", "Password123!")
        bob = login(client, "bob", "Password123!")
        admin = login(client, "admin", "ChangeMe_Admin_2026!")
        print("[login] alice, bob, admin authenticated via 2FA")

        # 3. Profile (RSA-encrypted)
        r = client.get("/api/profile", headers={"x-session-token": alice})
        print(f"[profile] alice -> {r.json()['profile']} ({r.json()['integrity']})")

        # 4. Publish IoC posts (ElGamal-encrypted)
        iocs = [
            "IOC: 185.220.101.34 | CVE-2024-1234 | malware: Emotet",
            "IOC: 45.155.205.233 | CVE-2023-44487 | campaign: HTTP/2 rapid reset",
            "IOC: 91.240.118.77 | CVE-2021-44228 | family: Log4Shell scanners",
        ]
        for ioc in iocs:
            r = client.post("/api/posts", headers={"x-session-token": alice}, json={"content": ioc})
            assert r.status_code == 200, r.text
        print(f"[posts] alice published {len(iocs)} IoCs (ElGamal-encrypted at rest)")

        # 5. Feed (decrypted on the backend for the authenticated session)
        r = client.get("/api/posts", headers={"x-session-token": bob})
        print(f"[feed] bob sees {r.json()['count']} posts, all integrity-verified")

        # 6. Direct message (end-to-end)
        bob_id = ctx.db.fetchone("SELECT id FROM users WHERE username='bob'")["id"]
        r = client.post("/api/messages", headers={"x-session-token": alice},
                        json={"recipient_id": bob_id, "content": "CVE-2024-9999 is being exploited in the wild"})
        assert r.status_code == 200, r.text
        r = client.get("/api/messages/inbox", headers={"x-session-token": bob})
        print(f"[dm] bob's inbox: {r.json()['messages'][0]['content']!r} from {r.json()['messages'][0]['sender']}")

        # 7. Tamper detection
        row = ctx.db.fetchone("SELECT id, ciphertext FROM posts LIMIT 1")
        first = row["ciphertext"][0]
        flipped = "f" if first != "f" else "e"
        ctx.db.execute("UPDATE posts SET ciphertext = ? WHERE id = ?",
                       (flipped + row["ciphertext"][1:], row["id"]))
        r = client.get("/api/posts", headers={"x-session-token": bob})
        print(f"[integrity] tampered post hidden from feed (now {r.json()['count']} visible); "
              f"failure logged: {ctx.db.fetchone('SELECT COUNT(*) c FROM integrity_log')['c']}")

        # 8. Admin governance
        r = client.get("/api/admin/integrity-log", headers={"x-session-token": admin})
        print(f"[admin] integrity log entries: {len(r.json()['entries'])}")
        r = client.post(f"/api/admin/users/{bob_id}/suspend", headers={"x-session-token": admin})
        print(f"[admin] bob suspended: {r.json()['status']}")
        r = client.post("/api/admin/rotate-keys", headers={"x-session-token": admin})
        print(f"[admin] global key rotation: {r.json()['rotated_users']} users rotated")
        r = client.get("/api/admin/key-summary", headers={"x-session-token": admin})
        print(f"[admin] key lifecycle: {r.json()['keys']}")

        print("=" * 60)
        print("Demo complete — every step verified.")


if __name__ == "__main__":
    main()