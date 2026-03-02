"""MongoDB connection and database initialization."""

import os
import logging
from dotenv import load_dotenv
from pymongo import MongoClient
import certifi

# Load environment variables from Vercel
load_dotenv()

logger = logging.getLogger(__name__)

# ── Connection setup ──────────────────────────────────────────────────────────
MONGO_CONNECTION_STRING = os.getenv("MONGO_DB_CONNECTION_STRING")

if not MONGO_CONNECTION_STRING:
    # Log a clear warning but don't crash at import time.
    # The function will start, and any DB-dependent route will fail with a
    # meaningful 503 error rather than a cryptic 500 FUNCTION_INVOCATION_FAILED.
    logger.error(
        "[STARTUP] MONGO_DB_CONNECTION_STRING is not set. "
        "All database operations will fail."
    )
    client = None
    db = None
    users_collection = None
else:
    try:
        # connect=False defers the actual TCP connection until the first query —
        # essential for serverless where we don't want connection overhead at startup.
        client = MongoClient(
            MONGO_CONNECTION_STRING,
            serverSelectionTimeoutMS=8000,   # fail fast on bad config
            connectTimeoutMS=8000,
            socketTimeoutMS=15000,
            tlsCAFile=certifi.where(),
            connect=False,
        )
        db = client["hackx_db"]
        users_collection = db["users"]
        logger.info("[STARTUP] MongoDB client initialised (connection deferred).")
    except Exception as exc:
        logger.exception("[STARTUP] Failed to create MongoDB client: %s", exc)
        client = None
        db = None
        users_collection = None


def ensure_indexes():
    """Create required indexes. Best-effort — never raises so the startup event
    doesn't crash the whole function on a cold start."""
    if client is None:
        logger.warning("[ensure_indexes] Skipped — no MongoDB client available.")
        return

    try:
        client.admin.command("ping")
        users_collection.create_index("email", unique=True)
        users_collection.create_index("created_at")
        logger.info("[ensure_indexes] MongoDB connected and indexes ensured.")
    except Exception as exc:
        # Log but never raise — a missing index is not fatal at startup.
        logger.warning("[ensure_indexes] Failed (non-fatal): %s", exc)
