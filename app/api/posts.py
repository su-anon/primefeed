"""Threat Intelligence Feed (CRUD).

- Posts are short IoC strings, encrypted with ElGamal before database insert.
- The feed is decrypted on the backend only for authenticated sessions.
- Every post is validated against its HMAC integrity badge on load; failures
  are logged to the system-wide integrity log.
"""

import time

from fastapi import APIRouter, Depends, HTTPException, Request

from ..core import config, security
from ..crypto import elgamal

router = APIRouter(prefix="/api/posts", tags=["posts"])


def _get_ctx(request: Request):
    return request.app.state.ctx


def _require_user(request: Request) -> int:
    """Resolve the session token to a user id (shared auth dependency)."""
    ctx = _get_ctx(request)
    urow = security.validate_session(ctx, request.headers.get("x-session-token", ""))
    if urow is None:
        raise HTTPException(401, "not authenticated")
    return urow["id"]


@router.get("")
def list_posts(request: Request, limit: int = 50, offset: int = 0):
    """Public feed: decrypt each post in memory for the authenticated viewer."""
    ctx = _get_ctx(request)
    _require_user(request)
    limit = min(max(limit, 1), 100)
    offset = max(offset, 0)

    rows = ctx.db.fetchall(
        "SELECT id, author_id, ciphertext, key_ref, hmac, created_at FROM posts ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, offset))

    posts = []
    for row in rows:
        if not security.verify_integrity_badge("post", row["id"], row["ciphertext"], row["hmac"], ctx.secret):
            security.log_integrity_failure(ctx.db, "post", row["id"], "HMAC mismatch on feed load")
            continue  # tampered record: never render it
        try:
            plain = ctx.key_manager.decrypt_elgamal(row["author_id"], row["ciphertext"], row["key_ref"])
        except Exception:
            continue  # undecryptable (e.g. key rotated): skip silently
        author = ctx.db.fetchone("SELECT username FROM users WHERE id = ?", (row["author_id"],))
        posts.append({
            "id": row["id"],
            "author_id": row["author_id"],
            "author": author["username"] if author else "unknown",
            "content": plain,
            "created_at": row["created_at"],
            "integrity": "verified",
        })
    return {"posts": posts, "count": len(posts)}


@router.post("")
def create_post(request: Request, body: dict):
    """Create a post: encrypt the IoC payload with ElGamal, badge it, store it."""
    ctx = _get_ctx(request)
    user_id = _require_user(request)
    content = (body.get("content") or "").strip()
    if not content:
        raise HTTPException(400, "content is required")
    if len(content) > config.MAX_POST_LENGTH:
        raise HTTPException(400, f"content exceeds {config.MAX_POST_LENGTH} characters")

    pub = ctx.key_manager.get_active_public_key(user_id, "ELGAMAL")
    pub_key = elgamal.parse_elgamal_public(pub)
    domain = elgamal.ElGamalDomain(pub_key["p"], pub_key["q"], pub_key["g"])
    ciphertext = domain.encrypt(pub_key["y"], content.encode()).hex()

    now = int(time.time())
    ctx.db.execute(
        "INSERT INTO posts (author_id, ciphertext, key_ref, hmac, created_at, updated_at) VALUES (?, ?, ?, '', ?, ?)",
        (user_id, ciphertext, pub, now, now))
    post_id = ctx.db.last_insert_id()
    badge = security.make_integrity_badge("post", post_id, ciphertext, ctx.secret)
    ctx.db.execute("UPDATE posts SET hmac = ? WHERE id = ?", (badge, post_id))

    return {"ok": True, "post_id": post_id}


@router.get("/{post_id}")
def get_post(request: Request, post_id: int):
    """Fetch and decrypt a single post (integrity-checked)."""
    ctx = _get_ctx(request)
    _require_user(request)
    row = ctx.db.fetchone(
        "SELECT id, author_id, ciphertext, key_ref, hmac, created_at FROM posts WHERE id = ?", (post_id,))
    if row is None:
        raise HTTPException(404, "post not found")
    if not security.verify_integrity_badge("post", row["id"], row["ciphertext"], row["hmac"], ctx.secret):
        security.log_integrity_failure(ctx.db, "post", row["id"], "HMAC mismatch on single fetch")
        raise HTTPException(409, "post integrity check failed")
    try:
        plain = ctx.key_manager.decrypt_elgamal(row["author_id"], row["ciphertext"], row["key_ref"])
    except Exception:
        raise HTTPException(409, "post cannot be decrypted with the current key (may have been rotated)")
    return {"id": row["id"], "author_id": row["author_id"], "content": plain,
            "created_at": row["created_at"], "integrity": "verified"}


@router.put("/{post_id}")
def update_post(request: Request, post_id: int, body: dict):
    """Edit a post (author-only). Re-encrypts and re-badges the payload."""
    ctx = _get_ctx(request)
    user_id = _require_user(request)
    row = ctx.db.fetchone("SELECT author_id FROM posts WHERE id = ?", (post_id,))
    if row is None:
        raise HTTPException(404, "post not found")
    if row["author_id"] != user_id:
        raise HTTPException(403, "you can only edit your own posts")

    content = (body.get("content") or "").strip()
    if not content or len(content) > config.MAX_POST_LENGTH:
        raise HTTPException(400, f"content must be 1-{config.MAX_POST_LENGTH} characters")

    pub = ctx.key_manager.get_active_public_key(user_id, "ELGAMAL")
    pub_key = elgamal.parse_elgamal_public(pub)
    domain = elgamal.ElGamalDomain(pub_key["p"], pub_key["q"], pub_key["g"])
    ciphertext = domain.encrypt(pub_key["y"], content.encode()).hex()
    badge = security.make_integrity_badge("post", post_id, ciphertext, ctx.secret)
    ctx.db.execute(
        "UPDATE posts SET ciphertext = ?, key_ref = ?, hmac = ?, updated_at = ? WHERE id = ?",
        (ciphertext, pub, badge, int(time.time()), post_id))
    return {"ok": True, "post_id": post_id}


@router.delete("/{post_id}")
def delete_post(request: Request, post_id: int):
    """Delete a post (author-only)."""
    ctx = _get_ctx(request)
    user_id = _require_user(request)
    row = ctx.db.fetchone("SELECT author_id FROM posts WHERE id = ?", (post_id,))
    if row is None:
        raise HTTPException(404, "post not found")
    if row["author_id"] != user_id:
        raise HTTPException(403, "you can only delete your own posts")
    ctx.db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    return {"ok": True}