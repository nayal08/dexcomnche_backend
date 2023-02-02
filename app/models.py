from sqlalchemy import Boolean, Column, Integer, String, TIMESTAMP
from .database import Base
import pytz
from datetime import datetime


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String)
    password = Column(String, nullable=True)
    email_verified = Column(Boolean, default=False, nullable=True)
    is_active = Column(Boolean, default=False)
    updated_at = Column(
        TIMESTAMP,
        default=datetime.now(tz=pytz.utc),
        onupdate=datetime.now(tz=pytz.utc),
    )


class AdminModel(Base):
    __tablename__ = "admins"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String, nullable=False)  
    password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    updated_at = Column(
        TIMESTAMP,
        default=datetime.utcnow(),
        onupdate=datetime.utcnow(),
    )
