#!/usr/bin/env bash
# PrimeFeed production launcher — full-strength keys.
#
# Uses:
#   * RSA-3072, ElGamal 2048/256, PBKDF2 10k  (128-bit security level)
#   * the real development database (data/primefeed.db)
#   * dev TOTP helper ON by default so the browser 2FA demo works without a
#     real authenticator app. IMPORTANT: set PRIMEFEED_DEV_TOTP_HELPER=0
#     before exposing the server publicly — it leaks current TOTP codes.
#
# NOTE: first registration with production keys takes ~2 min (pure-Python keygen).
set -euo pipefail
cd "$(dirname "$0")"

export PRIMEFEED_RSA_BITS="${PRIMEFEED_RSA_BITS:-3072}"
export PRIMEFEED_ELGAMAL_P_BITS="${PRIMEFEED_ELGAMAL_P_BITS:-2048}"
export PRIMEFEED_ELGAMAL_Q_BITS="${PRIMEFEED_ELGAMAL_Q_BITS:-256}"
export PRIMEFEED_PBKDF2_ITERATIONS="${PRIMEFEED_PBKDF2_ITERATIONS:-10000}"
export PRIMEFEED_DEV_TOTP_HELPER="${PRIMEFEED_DEV_TOTP_HELPER:-1}"

PORT="${PORT:-8001}"

echo "[prod] starting PrimeFeed on http://127.0.0.1:${PORT}  (full-strength keys)"
echo "[prod] dev TOTP helper ON (browser 2FA demo). Disable publicly: PRIMEFEED_DEV_TOTP_HELPER=0"
python3 run.py --port "${PORT}"