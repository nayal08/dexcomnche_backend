from pydantic import BaseModel, EmailStr, Field, ConstrainedStr
from typing import Optional
from datetime import datetime


# Users
class StrippedNotEmptyStrUser(ConstrainedStr):
    min_length = 1
    strip_whitespace = True


class Users(BaseModel):
    id: int
    name: StrippedNotEmptyStrUser
    email: EmailStr
    is_active: bool = False
    updated_at: datetime


class UserData(BaseModel):
    id: int
    name: Optional[str] = None
    email: str
    bio: Optional[str] = None
    user_image: Optional[str] = None

    class Config:
        orm_mode = True


class UserSignup(BaseModel):
    name: str
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=50, regex="^(?=.*[\w])(?=.*[\W])[\w\W]{8,}$")


class UserSignupSuccess(BaseModel):
    name: str
    email: EmailStr
    message: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOtp(BaseModel):
    email: EmailStr


class UserResetPassword(BaseModel):
    email: EmailStr
    otp: str = Field(..., min_length=6, max_length=6)
    password: str = Field(..., min_length=8, max_length=50, regex="^(?=.*[\w])(?=.*[\W])[\w\W]{8,}$")


class UserChangePassword(BaseModel):
    current_password: str = Field(..., min_length=8, max_length=50, regex="^(?=.*[\w])(?=.*[\W])[\w\W]{8,}$")
    new_password: str = Field(..., min_length=8, max_length=50, regex="^(?=.*[\w])(?=.*[\W])[\w\W]{8,}$")


class UserOauthLogin(BaseModel):
    name: str
    email: EmailStr
    provider: str
    provider_id: str


class UserFetch(BaseModel):
    id: int
    email: str
    is_active: bool
    updated_at: datetime


# Admin


class AdminFetch(BaseModel):
    id: int
    email: str
    is_active: bool
    updated_at: datetime
