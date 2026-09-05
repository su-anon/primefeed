"""Personal encrypted profile management.

Users can read and update their own RSA-encrypted profile. Updates are
re-encrypted with the user's active RSA public key and re-badged.
"""

import json
import time

from fastapi import APIRouter, HTTPException, Request

from ..core import security
from ..crypto import rsa

router = APIRouter(prefix="/api/profile", tags=["profile"])


def _get_ctx(request: Request):
    return request.app.state.ctx


def _require_user(request: Request) -> int:
    ctx = _get_ctx(request)
    urow = security.validate_session(ctx, request.headers.get("x-session-token", ""))
    if urow is None:
        raise HTTPException(401, "not authenticated")
    return urow["id"]


@router.get("")
def get_profile(request: Request):
    """Decrypt and return the caller's own profile."""
    ctx = _get_ctx(request)
    user_id = _require_user(request)
    row = ctx.db.fetchone("SELECT encrypted, key_ref, hmac FROM profiles WHERE user_id = ?", (user_id,))
    if row is None:
        raise HTTPException(404, "profile not found")
    if not security.verify_integrity_badge("profile", user_id, row["encrypted"], row["hmac"], ctx.secret):
        security.log_integrity_failure(ctx.db, "profile", user_id, "HMAC mismatch on profile load")
        raise HTTPException(409, "profile integrity check failed")
    try:
        plain = ctx.key_manager.decrypt_rsa(user_id, row["encrypted"], row["key_ref"])
    except Exception:
        raise HTTPException(409, "profile cannot be decrypted (key may have been rotated)")
    return {"profile": json.loads(plain), "integrity": "verified"}


@router.put("")
def update_profile(request: Request, body: dict):
    """Update the caller's own profile (re-encrypt + re-badge)."""
    ctx = _get_ctx(request)
    user_id = _require_user(request)
    email = (body.get("email") or "").strip()
    name = (body.get("name") or "").strip()
    contact = (body.get("contact") or "").strip()
    if not email:
        raise HTTPException(400, "email is required")

    pub = ctx.key_manager.get_active_public_key(user_id, "RSA")
    pub_key = rsa.parse_rsa_public(pub)
    payload = json.dumps({"email": email, "name": name, "contact": contact}).encode()
    ciphertext = rsa.rsa_encrypt_bytes(pub_key, payload).hex()
    badge = security.make_integrity_badge("profile", user_id, ciphertext, ctx.secret)
    ctx.db.execute(
        """INSERT INTO profiles (user_id, encrypted, key_ref, hmac, updated_at) VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(user_id) DO UPDATE SET encrypted = excluded.encrypted,
                                              key_ref = excluded.key_ref,
                                              hmac = excluded.hmac,
                                              updated_at = excluded.updated_at""",
        (user_id, ciphertext, pub, badge, int(time.time())))
    return {"ok": True}