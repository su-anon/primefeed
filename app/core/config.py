"""Application configuration.

All values can be overridden with environment variables. The server secret and
master key are generated on first boot and persisted under the data directory,
so sessions and the vault survive restarts.
"""

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DATABASE_PATH = os.environ.get("PRIMEFEED_DB", os.path.join(DATA_DIR, "primefeed.db"))
DOMAIN_PARAMS_PATH = os.path.join(DATA_DIR, "elgamal_domain.json")
MASTER_KEY_PATH = os.path.join(DATA_DIR, "master_key.json")
SECRET_PATH = os.path.join(DATA_DIR, "server_secret.txt")

# Crypto period: how long a key stays in active use before it must be rotated.
CRYPTO_PERIOD_DAYS = int(os.environ.get("PRIMEFEED_CRYPTO_PERIOD_DAYS", "90"))

# Key sizes. Production defaults: RSA-3072 (128-bit security), ElGamal over a
# 2048-bit Schnorr group with a 256-bit prime-order subgroup. Tests override
# these with small values so the suite runs in seconds.
RSA_KEY_BITS = int(os.environ.get("PRIMEFEED_RSA_BITS", "3072"))
ELGAMAL_P_BITS = int(os.environ.get("PRIMEFEED_ELGAMAL_P_BITS", "2048"))
ELGAMAL_Q_BITS = int(os.environ.get("PRIMEFEED_ELGAMAL_Q_BITS", "256"))

# Password hashing cost (PBKDF2-HMAC-SHA256 iterations).
# Pure-Python SHA-256 is ~100-200x slower than C, so 120k iterations would make
# every login take ~70s. 10k iterations (~6s per login) keeps the engine usable
# while still being slow to brute-force; raise it on faster runtimes.
PBKDF2_ITERATIONS = int(os.environ.get("PRIMEFEED_PBKDF2_ITERATIONS", "10000"))

# Session lifetime in seconds (24h).
SESSION_TTL_SECONDS = int(os.environ.get("PRIMEFEED_SESSION_TTL", str(24 * 3600)))

# TOTP settings.
TOTP_DIGITS = 6
TOTP_TIME_STEP = 30
TOTP_WINDOW = 1

# IoC post limits (kept small to stay within pure-asymmetric math limits).
MAX_POST_LENGTH = 500
MAX_MESSAGE_LENGTH = 500

# Bootstrap admin (created on first boot if no users exist).
ADMIN_USERNAME = os.environ.get("PRIMEFEED_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("PRIMEFEED_ADMIN_PASSWORD", "temporary_admin_password")
ADMIN_EMAIL = os.environ.get("PRIMEFEED_ADMIN_EMAIL", "admin@primefeed.local")

# Dev-only TOTP helper (see app/api/dev.py). Disable in production!
DEV_TOTP_HELPER = os.environ.get("PRIMEFEED_DEV_TOTP_HELPER", "1") == "1"

# Frontend static directory — the designed pages now live INSIDE the backend
# project (Backend/frontend), so the whole app is one folder.
FRONTEND_DIR = os.environ.get("PRIMEFEED_FRONTEND_DIR", os.path.join(BASE_DIR, "frontend"))