import os
from typing import Optional, Dict, Any
from datetime import datetime

DB_BACKEND = os.getenv("DB_BACKEND", "sqlite")

# --- SQLite (SQLAlchemy) Backend ---
class SQLiteBackend:
    from sqlalchemy.orm import Session
    from models import User

    @staticmethod
    def get_user_by_email(db, email: str):
        return db.query(SQLiteBackend.User).filter(SQLiteBackend.User.email == email).first()

    @staticmethod
    def get_user_by_id(db, user_id: int):
        return db.query(SQLiteBackend.User).filter(SQLiteBackend.User.id == user_id).first()

    @staticmethod
    def get_user_by_reset_token(db, token: str):
        return db.query(SQLiteBackend.User).filter(SQLiteBackend.User.reset_token == token, SQLiteBackend.User.reset_token_expires > datetime.utcnow()).first()

    @staticmethod
    def create_user(db, user_data: dict):
        user = SQLiteBackend.User(**user_data)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def update_user(db, email: str, update_data: dict):
        user = SQLiteBackend.get_user_by_email(db, email)
        if not user:
            return None
        for k, v in update_data.items():
            setattr(user, k, v)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def delete_user(db, email: str):
        user = SQLiteBackend.get_user_by_email(db, email)
        if user:
            db.delete(user)
            db.commit()

    @staticmethod
    def get_all_users(db):
        return db.query(SQLiteBackend.User).all()

# --- MongoDB (Motor) Backend ---
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGO_URL)
mongo_db = client["auth_db"]
users_collection = mongo_db["users"]

class UserModel(BaseModel):
    id: Optional[str]
    email: EmailStr
    password_hash: str
    full_name: str
    is_active: bool = True
    is_admin: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    reset_token: Optional[str] = None
    reset_token_expires: Optional[datetime] = None

class MongoBackend:
    @staticmethod
    async def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
        user = await users_collection.find_one({"email": email})
        if user:
            user["id"] = str(user["_id"])
            user["email"] = user.get("email")
        return user

    @staticmethod
    async def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
        user = await users_collection.find_one({"id": user_id})
        if user:
            user["id"] = str(user["_id"])
            user["email"] = user.get("email")
        return user

    @staticmethod
    async def get_user_by_reset_token(token: str) -> Optional[Dict[str, Any]]:
        now = datetime.utcnow()
        user = await users_collection.find_one({"reset_token": token, "reset_token_expires": {"$gt": now}})
        if user:
            user["id"] = str(user["_id"])
            user["email"] = user.get("email")
        return user

    @staticmethod
    async def create_user(user_data: dict) -> str:
        result = await users_collection.insert_one(user_data)
        return str(result.inserted_id)

    @staticmethod
    async def update_user(email: str, update_data: dict):
        await users_collection.update_one({"email": email}, {"$set": update_data})

    @staticmethod
    async def delete_user(email: str):
        await users_collection.delete_one({"email": email})

    @staticmethod
    async def get_all_users():
        users = []
        async for user in users_collection.find():
            user["id"] = str(user["_id"])
            user["email"] = user.get("email")
            users.append(user)
        return users

# --- Dispatch functions ---
if DB_BACKEND == "sqlite":
    get_user_by_email = SQLiteBackend.get_user_by_email
    get_user_by_id = SQLiteBackend.get_user_by_id
    get_user_by_reset_token = SQLiteBackend.get_user_by_reset_token
    create_user = SQLiteBackend.create_user
    update_user = SQLiteBackend.update_user
    delete_user = SQLiteBackend.delete_user
    get_all_users = SQLiteBackend.get_all_users
else:
    get_user_by_email = MongoBackend.get_user_by_email
    get_user_by_id = MongoBackend.get_user_by_id
    get_user_by_reset_token = MongoBackend.get_user_by_reset_token
    create_user = MongoBackend.create_user
    update_user = MongoBackend.update_user
    delete_user = MongoBackend.delete_user
    get_all_users = MongoBackend.get_all_users 