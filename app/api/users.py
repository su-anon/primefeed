"""Public user directory — used by the messaging composer to pick a recipient.

Only exposes username/role for active (non-suspended) accounts.
"""

from fastapi import APIRouter, HTTPException, Request

from ..core import security

router = APIRouter(prefix="/api/users", tags=["users"])


def _require_user(request: Request) -> int:
    ctx = request.app.state.ctx
    urow = security.validate_session(ctx, request.headers.get("x-session-token", ""))
    if urow is None:
        raise HTTPException(401, "not authenticated")
    return urow["id"]


@router.get("")
def list_users(request: Request):
    """List active users (id + username + role) for messaging."""
    _require_user(request)
    ctx = request.app.state.ctx
    rows = ctx.db.fetchall(
        "SELECT id, username, role FROM users WHERE is_suspended = 0 ORDER BY username")
    return {"users": [dict(r) for r in rows]}