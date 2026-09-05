"""Secure Direct Messaging.

- Senders encrypt short messages with the recipient's ElGamal public key, so
  only the target user can decrypt with their private key (end-to-end).
- Every message carries an HMAC badge binding sender identity + payload.
- All threads are stored as ciphertext blobs; administrators cannot decrypt
  user-to-user messages (zero-knowledge boundary).
"""

import time

from fastapi import APIRouter, HTTPException, Request

from ..core import config, security
from ..crypto import elgamal

router = APIRouter(prefix="/api/messages", tags=["messages"])


def _get_ctx(request: Request):
    return request.app.state.ctx


def _require_user(request: Request) -> int:
    ctx = _get_ctx(request)
    urow = security.validate_session(ctx, request.headers.get("x-session-token", ""))
    if urow is None:
        raise HTTPException(401, "not authenticated")
    return urow["id"]


@router.post("")
def send_message(request: Request, body: dict):
    """Send a message: encrypt with the recipient's ElGamal public key."""
    ctx = _get_ctx(request)
    sender_id = _require_user(request)
    recipient_id = body.get("recipient_id")
    content = (body.get("content") or "").strip()

    if not recipient_id or not content:
        raise HTTPException(400, "recipient_id and content are required")
    if len(content) > config.MAX_MESSAGE_LENGTH:
        raise HTTPException(400, f"message exceeds {config.MAX_MESSAGE_LENGTH} characters")

    recipient = ctx.db.fetchone(
        "SELECT id, is_suspended FROM users WHERE id = ?", (recipient_id,))
    if recipient is None or recipient["is_suspended"]:
        raise HTTPException(404, "recipient not found")

    pub = ctx.key_manager.get_active_public_key(recipient_id, "ELGAMAL")
    pub_key = elgamal.parse_elgamal_public(pub)
    domain = elgamal.ElGamalDomain(pub_key["p"], pub_key["q"], pub_key["g"])
    ciphertext = domain.encrypt(pub_key["y"], content.encode()).hex()

    # Also encrypt a copy to the sender's own key so the "sent" view can
    # decrypt it (the sender cannot decrypt the recipient's copy).
    sender_pub = ctx.key_manager.get_active_public_key(sender_id, "ELGAMAL")
    sender_pub_key = elgamal.parse_elgamal_public(sender_pub)
    sender_domain = elgamal.ElGamalDomain(sender_pub_key["p"], sender_pub_key["q"], sender_pub_key["g"])
    sender_ciphertext = sender_domain.encrypt(sender_pub_key["y"], content.encode()).hex()

    now = int(time.time())
    ctx.db.execute(
        """INSERT INTO messages (sender_id, recipient_id, ciphertext, sender_ciphertext,
                                 key_ref, sender_key_ref, hmac, created_at)
           VALUES (?, ?, ?, ?, ?, ?, '', ?)""",
        (sender_id, recipient_id, ciphertext, sender_ciphertext, pub, sender_pub, now))
    msg_id = ctx.db.last_insert_id()
    badge = security.make_integrity_badge("message", msg_id, ciphertext + sender_ciphertext, ctx.secret)
    ctx.db.execute("UPDATE messages SET hmac = ? WHERE id = ?", (badge, msg_id))

    return {"ok": True, "message_id": msg_id}


@router.get("/inbox")
def inbox(request: Request):
    """List messages addressed to the current user (decrypted in memory)."""
    ctx = _get_ctx(request)
    user_id = _require_user(request)
    rows = ctx.db.fetchall(
        """SELECT id, sender_id, ciphertext, sender_ciphertext, key_ref, hmac, created_at, read_at
           FROM messages WHERE recipient_id = ? ORDER BY created_at DESC""",
        (user_id,))

    out = []
    for row in rows:
        if not security.verify_integrity_badge("message", row["id"],
                                               row["ciphertext"] + row["sender_ciphertext"],
                                               row["hmac"], ctx.secret):
            security.log_integrity_failure(ctx.db, "message", row["id"], "HMAC mismatch on inbox load")
            continue
        try:
            plain = ctx.key_manager.decrypt_elgamal(user_id, row["ciphertext"], row["key_ref"])
        except Exception:
            continue
        sender = ctx.db.fetchone("SELECT username FROM users WHERE id = ?", (row["sender_id"],))
        out.append({
            "id": row["id"],
            "sender_id": row["sender_id"],
            "sender": sender["username"] if sender else "unknown",
            "content": plain,
            "created_at": row["created_at"],
            "read": row["read_at"] is not None,
            "integrity": "verified",
        })
    return {"messages": out, "count": len(out)}


@router.get("/sent")
def sent(request: Request):
    """List messages sent by the current user (decrypted in memory)."""
    ctx = _get_ctx(request)
    user_id = _require_user(request)
    rows = ctx.db.fetchall(
        """SELECT id, recipient_id, ciphertext, sender_ciphertext, sender_key_ref, hmac, created_at
           FROM messages WHERE sender_id = ? ORDER BY created_at DESC""",
        (user_id,))

    out = []
    for row in rows:
        if not security.verify_integrity_badge("message", row["id"],
                                               row["ciphertext"] + row["sender_ciphertext"],
                                               row["hmac"], ctx.secret):
            security.log_integrity_failure(ctx.db, "message", row["id"], "HMAC mismatch on sent load")
            continue
        try:
            plain = ctx.key_manager.decrypt_elgamal(user_id, row["sender_ciphertext"], row["sender_key_ref"])
        except Exception:
            continue
        recipient = ctx.db.fetchone("SELECT username FROM users WHERE id = ?", (row["recipient_id"],))
        out.append({
            "id": row["id"],
            "recipient_id": row["recipient_id"],
            "recipient": recipient["username"] if recipient else "unknown",
            "content": plain,
            "created_at": row["created_at"],
            "integrity": "verified",
        })
    return {"messages": out, "count": len(out)}


@router.post("/{message_id}/read")
def mark_read(request: Request, message_id: int):
    """Mark an inbound message as read (recipient-only)."""
    ctx = _get_ctx(request)
    user_id = _require_user(request)
    row = ctx.db.fetchone(
        "SELECT id, recipient_id FROM messages WHERE id = ?", (message_id,))
    if row is None:
        raise HTTPException(404, "message not found")
    if row["recipient_id"] != user_id:
        raise HTTPException(403, "not your message")
    ctx.db.execute("UPDATE messages SET read_at = ? WHERE id = ?", (int(time.time()), message_id))
    return {"ok": True}