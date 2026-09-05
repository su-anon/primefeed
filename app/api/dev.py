"""Development-only helpers.

WARNING: These endpoints are for local development only. They are enabled by
``PRIMEFEED_DEV_TOTP_HELPER`` (default 1) and MUST be disabled (set to 0) in
any deployed environment -- they leak the current TOTP code for any username.
"""

from fastapi import APIRouter, HTTPException, Request

from ..core import config
from ..crypto import totp

router = APIRouter(prefix="/api/dev", tags=["dev"])


@router.get("/totp/{username}")
def dev_current_totp(request: Request, username: str):
    """Return the current TOTP code for ``username`` (dev convenience only)."""
    if not config.DEV_TOTP_HELPER:
        raise HTTPException(404, "dev helper disabled")
    ctx = request.app.state.ctx
    row = ctx.db.fetchone("SELECT totp_secret FROM users WHERE username = ?", (username,))
    if row is None:
        raise HTTPException(404, "no such user")
    return {"username": username, "code": totp.totp_code(row["totp_secret"]),
            "note": "dev-only helper; disable with PRIMEFEED_DEV_TOTP_HELPER=0"}