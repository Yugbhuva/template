from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, String, Boolean, DateTime
from datetime import datetime
from typing import Optional

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String)
    full_name: Mapped[str] = mapped_column(String)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    reset_token: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    reset_token_expires: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True) 