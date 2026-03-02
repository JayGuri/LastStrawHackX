"""User model and database operations."""

import logging
import bcrypt
from datetime import datetime
from api.client import db, users_collection

logger = logging.getLogger(__name__)


class User:
    """User model for authentication."""

    @staticmethod
    def create_user(email, password=None, subscription_level="free", auth_provider="local"):
        if users_collection is None:
            raise RuntimeError("Database not available")

        hashed_password = None
        if password:
            hashed_password = bcrypt.hashpw(
                password.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")

        user_doc = {
            "email": email,
            "password": hashed_password,
            "subscription_level": subscription_level,
            "auth_provider": auth_provider,
            "created_at": datetime.utcnow(),
        }

        result = users_collection.insert_one(user_doc)
        logger.info("[User.create_user] Created user id=%s email=%s", result.inserted_id, email)
        return users_collection.find_one({"_id": result.inserted_id})

    @staticmethod
    def find_by_email(email):
        if users_collection is None:
            raise RuntimeError("Database not available")
        return users_collection.find_one({"email": email})

    @staticmethod
    def find_by_id(user_id):
        if users_collection is None:
            raise RuntimeError("Database not available")
        from bson.objectid import ObjectId
        try:
            return users_collection.find_one({"_id": ObjectId(user_id)})
        except Exception as exc:
            logger.warning("[User.find_by_id] Invalid id=%s: %s", user_id, exc)
            return None

    @staticmethod
    def verify_password(stored_hash, plain_password):
        return bcrypt.checkpw(
            plain_password.encode("utf-8"), stored_hash.encode("utf-8")
        )

    @staticmethod
    def user_to_dict(user_doc):
        if not user_doc:
            return None
        return {
            "id": str(user_doc["_id"]),
            "email": user_doc["email"],
            "subscription_level": user_doc["subscription_level"],
            "auth_provider": user_doc["auth_provider"],
            "created_at": user_doc["created_at"].isoformat(),
        }
