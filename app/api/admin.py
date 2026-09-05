"""Administrator governance (RBAC).

Admins can: suspend/restore user accounts, trigger global key rotation, and
review the system-wide HMAC integrity failure log. They CANNOT decrypt private
user-to-user messages (zero-knowledge boundary is enforced by the crypto
design, not by policy).
"""

import time

from fastapi import APIRouter, HTTPException, Request

from ..core import security

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _get_ctx(request: Request):
    return request.app.state.ctx


def _require_admin(request: Request) -> int:
    ctx = _get_ctx(request)
    urow = security.validate_session(ctx, request.headers.get("x-session-token", ""))
    if urow is None:
        raise HTTPException(401, "not authenticated")
    if urow["role"] != "admin":
        raise HTTPException(403, "administrator privileges required")
    return urow["id"]


@router.get("/users")
def list_users(request: Request):
    """List all users with role and suspension state."""
    ctx = _get_ctx(request)
    _require_admin(request)
    rows = ctx.db.fetchall(
        "SELECT id, username, role, is_suspended, created_at FROM users ORDER BY id")
    return {"users": [dict(r) for r in rows]}


@router.post("/users/{user_id}/suspend")
def suspend_user(request: Request, user_id: int):
    """Suspend a compromised account and destroy its keys."""
    ctx = _get_ctx(request)
    _require_admin(request)
    row = ctx.db.fetchone("SELECT id, role FROM users WHERE id = ?", (user_id,))
    if row is None:
        raise HTTPException(404, "user not found")
    if row["role"] == "admin":
        raise HTTPException(400, "cannot suspend an administrator")
    ctx.db.execute("UPDATE users SET is_suspended = 1 WHERE id = ?", (user_id,))
    ctx.key_manager.destroy_user_keys(user_id)
    ctx.db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    return {"ok": True, "user_id": user_id, "status": "suspended"}


@router.post("/users/{user_id}/restore")
def restore_user(request: Request, user_id: int):
    """Restore a suspended account (keys are regenerated on next login flow)."""
    ctx = _get_ctx(request)
    _require_admin(request)
    row = ctx.db.fetchone("SELECT id FROM users WHERE id = ?", (user_id,))
    if row is None:
        raise HTTPException(404, "user not found")
    ctx.db.execute("UPDATE users SET is_suspended = 0 WHERE id = ?", (user_id,))
    return {"ok": True, "user_id": user_id, "status": "restored"}


@router.post("/rotate-keys")
def rotate_keys(request: Request):
    """Trigger a global cryptographic key rotation (crypto period enforcement)."""
    ctx = _get_ctx(request)
    _require_admin(request)
    rotated = ctx.key_manager.rotate_all_keys()
    return {"ok": True, "rotated_users": rotated}


@router.get("/integrity-log")
def integrity_log(request: Request, limit: int = 100):
    """Review system-wide HMAC integrity failure records."""
    ctx = _get_ctx(request)
    _require_admin(request)
    limit = min(max(limit, 1), 500)
    rows = ctx.db.fetchall(
        "SELECT id, record_type, record_id, reason, created_at FROM integrity_log ORDER BY id DESC LIMIT ?",
        (limit,))
    return {"entries": [dict(r) for r in rows]}


@router.get("/key-summary")
def key_summary(request: Request):
    """Key lifecycle summary (active/deactivated/destroyed per algorithm)."""
    ctx = _get_ctx(request)
    _require_admin(request)
    return {"keys": ctx.key_manager.key_status_summary()}


# --- Public feed moderation -------------------------------------------------

@router.get("/posts")
def admin_posts(request: Request, limit: int = 100):
    """List all posts with decrypted content for moderation review."""
    ctx = _get_ctx(request)
    _require_admin(request)
    limit = min(max(limit, 1), 500)
    rows = ctx.db.fetchall(
        """SELECT id, author_id, ciphertext, key_ref, hmac, created_at,
                  (SELECT COUNT(*) FROM comments c WHERE c.post_id = posts.id) AS comment_count
           FROM posts ORDER BY created_at DESC LIMIT ?""", (limit,))
    out = []
    for row in rows:
        verified = security.verify_integrity_badge("post", row["id"], row["ciphertext"], row["hmac"], ctx.secret)
        content = None
        if verified:
            try:
                content = ctx.key_manager.decrypt_elgamal(row["author_id"], row["ciphertext"], row["key_ref"])
            except Exception:
                content = None
        author = ctx.db.fetchone("SELECT username FROM users WHERE id = ?", (row["author_id"],))
        out.append({
            "id": row["id"],
            "author": author["username"] if author else "?",
            "content": content,
            "integrity": "verified" if verified else "TAMPERED",
            "comment_count": row["comment_count"],
            "created_at": row["created_at"],
        })
    return {"posts": out}


@router.delete("/posts/{post_id}")
def admin_delete_post(request: Request, post_id: int):
    """Delete any post (moderation); also removes its comments."""
    ctx = _get_ctx(request)
    _require_admin(request)
    if ctx.db.fetchone("SELECT id FROM posts WHERE id = ?", (post_id,)) is None:
        raise HTTPException(404, "post not found")
    ctx.db.execute("DELETE FROM comments WHERE post_id = ?", (post_id,))
    ctx.db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    return {"ok": True, "post_id": post_id, "action": "moderated"}


# --- User lifecycle governance ---------------------------------------------

@router.post("/users/{user_id}/elevate")
def elevate_user(request: Request, user_id: int):
    """Elevate a regular user to administrator."""
    ctx = _get_ctx(request)
    _require_admin(request)
    row = ctx.db.fetchone("SELECT id, role FROM users WHERE id = ?", (user_id,))
    if row is None:
        raise HTTPException(404, "user not found")
    if row["role"] == "admin":
        return {"ok": True, "user_id": user_id, "role": "admin", "message": "already an administrator"}
    ctx.db.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
    return {"ok": True, "user_id": user_id, "role": "admin"}


@router.post("/users/{user_id}/reset-2fa")
def reset_2fa(request: Request, user_id: int):
    """Generate a new TOTP secret for a locked-out user and revoke sessions."""
    from ..crypto import totp
    ctx = _get_ctx(request)
    _require_admin(request)
    if ctx.db.fetchone("SELECT id FROM users WHERE id = ?", (user_id,)) is None:
        raise HTTPException(404, "user not found")
    secret = totp.generate_totp_secret()
    ctx.db.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user_id))
    ctx.db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    return {"ok": True, "user_id": user_id, "totp_secret": secret}


@router.post("/users/{user_id}/reset-password")
def reset_password(request: Request, user_id: int):
    """Set a temporary password for a locked-out user and revoke sessions."""
    from ..core import security as _sec
    from ..crypto.math_utils import random_bytes
    ctx = _get_ctx(request)
    _require_admin(request)
    if ctx.db.fetchone("SELECT id FROM users WHERE id = ?", (user_id,)) is None:
        raise HTTPException(404, "user not found")
    temp = random_bytes(9).hex()  # 18 hex chars
    hash_hex, salt_hex = _sec.hash_password(temp)
    ctx.db.execute("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?", (hash_hex, salt_hex, user_id))
    ctx.db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    return {"ok": True, "user_id": user_id, "temporary_password": temp}