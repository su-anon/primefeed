#!/usr/bin/env bash
# PrimeFeed dev launcher — small keys for fast iteration.
#
# Uses:
#   * RSA-1024  (production is 3072)
#   * ElGamal 512/128-bit group  (production is 2048/256)
#   * PBKDF2 1,000 iterations  (production is 10,000)
#   * the real development database (data/primefeed.db)
#
# Registering new users takes ~1 second instead of ~2 minutes.
set -euo pipefail
cd "$(dirname "$0")"

export PRIMEFEED_RSA_BITS="${PRIMEFEED_RSA_BITS:-1024}"
export PRIMEFEED_ELGAMAL_P_BITS="${PRIMEFEED_ELGAMAL_P_BITS:-512}"
export PRIMEFEED_ELGAMAL_Q_BITS="${PRIMEFEED_ELGAMAL_Q_BITS:-128}"
export PRIMEFEED_PBKDF2_ITERATIONS="${PRIMEFEED_PBKDF2_ITERATIONS:-1000}"
export PRIMEFEED_DEV_TOTP_HELPER="${PRIMEFEED_DEV_TOTP_HELPER:-1}"

PORT="${PORT:-8001}"

echo "[dev] starting PrimeFeed on http://127.0.0.1:${PORT}  (small keys, dev TOTP helper ON)"
echo "[dev] db: data/primefeed.db"
python3 run.py --port "${PORT}"