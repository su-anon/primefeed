"""Comments on feed posts.

Like posts, every comment is ElGamal-encrypted with the commenter's public key
before storage and carries an HMAC integrity badge. Comments are decrypted in
memory only for authenticated readers.
"""

import time

from fastapi import APIRouter, HTTPException, Request

from ..core import config, security
from ..crypto import elgamal

router = APIRouter(prefix="/api", tags=["comments"])


def _get_ctx(request: Request):
    return request.app.state.ctx


def _require_user(request: Request) -> int:
    ctx = _get_ctx(request)
    urow = security.validate_session(ctx, request.headers.get("x-session-token", ""))
    if urow is None:
        raise HTTPException(401, "not authenticated")
    return urow["id"]


def _encrypt(ctx, user_id: int, content: str) -> tuple[str, str]:
    """Returns (ciphertext_hex, key_ref) encrypted to the user's active key."""
    pub = ctx.key_manager.get_active_public_key(user_id, "ELGAMAL")
    k = elgamal.parse_elgamal_public(pub)
    d = elgamal.ElGamalDomain(k["p"], k["q"], k["g"])
    return d.encrypt(k["y"], content.encode()).hex(), pub


def _decrypt_row(ctx, row) -> str | None:
    try:
        return ctx.key_manager.decrypt_elgamal(row["author_id"], row["ciphertext"], row["key_ref"])
    except Exception:
        return None


@router.get("/posts/{post_id}/comments")
def list_comments(request: Request, post_id: int):
    """List comments for a post (integrity-checked, decrypted in memory)."""
    ctx = _get_ctx(request)
    _require_user(request)
    post = ctx.db.fetchone("SELECT id FROM posts WHERE id = ?", (post_id,))
    if post is None:
        raise HTTPException(404, "post not found")
    rows = ctx.db.fetchall(
        "SELECT id, post_id, author_id, ciphertext, key_ref, hmac, created_at FROM comments WHERE post_id = ? ORDER BY created_at ASC",
        (post_id,))
    out = []
    for row in rows:
        if not security.verify_integrity_badge("comment", row["id"], row["ciphertext"], row["hmac"], ctx.secret):
            security.log_integrity_failure(ctx.db, "comment", row["id"], "HMAC mismatch on comment load")
            continue
        plain = _decrypt_row(ctx, row)
        if plain is None:
            continue
        author = ctx.db.fetchone("SELECT username FROM users WHERE id = ?", (row["author_id"],))
        out.append({
            "id": row["id"],
            "post_id": row["post_id"],
            "author_id": row["author_id"],
            "author": author["username"] if author else "unknown",
            "content": plain,
            "created_at": row["created_at"],
            "integrity": "verified",
        })
    return {"comments": out, "count": len(out)}


@router.post("/posts/{post_id}/comments")
def add_comment(request: Request, post_id: int, body: dict):
    """Add a comment: ElGamal-encrypt with the commenter's key, badge, store."""
    ctx = _get_ctx(request)
    user_id = _require_user(request)
    content = (body.get("content") or "").strip()
    if not content:
        raise HTTPException(400, "comment content is required")
    if len(content) > config.MAX_MESSAGE_LENGTH:
        raise HTTPException(400, f"comment exceeds {config.MAX_MESSAGE_LENGTH} characters")
    post = ctx.db.fetchone("SELECT id FROM posts WHERE id = ?", (post_id,))
    if post is None:
        raise HTTPException(404, "post not found")

    ct, key_ref = _encrypt(ctx, user_id, content)
    now = int(time.time())
    ctx.db.execute(
        "INSERT INTO comments (post_id, author_id, ciphertext, key_ref, hmac, created_at) VALUES (?, ?, ?, ?, '', ?)",
        (post_id, user_id, ct, key_ref, now))
    cid = ctx.db.last_insert_id()
    badge = security.make_integrity_badge("comment", cid, ct, ctx.secret)
    ctx.db.execute("UPDATE comments SET hmac = ? WHERE id = ?", (badge, cid))
    return {"ok": True, "comment_id": cid}


@router.delete("/comments/{comment_id}")
def delete_comment(request: Request, comment_id: int):
    """Delete a comment (author, or admin as moderator)."""
    ctx = _get_ctx(request)
    user_id = _require_user(request)
    row = ctx.db.fetchone("SELECT author_id FROM comments WHERE id = ?", (comment_id,))
    if row is None:
        raise HTTPException(404, "comment not found")
    if row["author_id"] != user_id:
        me = ctx.db.fetchone("SELECT role FROM users WHERE id = ?", (user_id,))
        if me is None or me["role"] != "admin":
            raise HTTPException(403, "you can only delete your own comments")
    ctx.db.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    return {"ok": True}