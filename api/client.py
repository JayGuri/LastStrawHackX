"""MongoDB connection and database initialization."""

import os
from dotenv import load_dotenv
from pymongo import MongoClient
import certifi

# Load environment variables from Vercel
load_dotenv()

# ── Connection setup ──────────────────────────────────────────────────────────
MONGO_CONNECTION_STRING = os.getenv("MONGO_DB_CONNECTION_STRING")

if not MONGO_CONNECTION_STRING:
    print("WARNING: MONGO_DB_CONNECTION_STRING is not set. Database calls will fail.")
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
    except Exception as exc:
        print(f"Failed to create MongoDB client: {exc}")
        client = None
        db = None
        users_collection = None


def ensure_indexes():
    """Create required indexes. Best-effort — never raises."""
    if client is None:
        return

    try:
        client.admin.command("ping")
        users_collection.create_index("email", unique=True)
        users_collection.create_index("created_at")
    except Exception as exc:
        print(f"Index creation failed (non-fatal): {exc}")
