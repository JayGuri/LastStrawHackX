"""User model and database operations."""

import bcrypt
from datetime import datetime
from api.client import db, users_collection


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
        except Exception:
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
