import requests
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from ..schemas.user_schema import UserFetch
from ..database import SessionLocal, get_db
from ..models import UserModel
from passlib.context import CryptContext
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from datetime import datetime, timedelta
from jose import jwt, JWTError
import redis
import os
import uuid
from ..commons.error_msg import ERR_SESSION_EXPIRED
import math
import random
import traceback
from typing import Any, Optional, Union
import os.path
from pathlib import Path
from dotenv import dotenv_values

config_credentials = dotenv_values(".env")


template_path = Path(__file__).parent.parent.absolute().joinpath("templates")

ENV_MODE = os.getenv("ENV_MODE")

REDIS_HOST = config_credentials["REDIS_HOST"]
REDIS_PORT = config_credentials["REDIS_PORT"]

router = APIRouter()
POOL = redis.ConnectionPool(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
redisClient = redis.StrictRedis(connection_pool=POOL, decode_responses=True)

jwt_secret = config_credentials["JWT_SECRET_KEY"]
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# House of Commons
def jsonify_res(**args):
    res = {}
    for arg in args.items():
        res[arg[0]] = arg[1]
    return JSONResponse(res)


def schema_to_dict(**args):
    for arg in args.items():
        print(arg)


def error_handler(value):
    def decorate(f):
        def applicator(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except Exception as e:
                traceback.print_exc()
                print(e)
                return value

        return applicator

    return decorate


def requests_wrapper(method, url, headers, data={}):
    response = requests.request(method, url=url, headers=headers, data=data)
    return response.text


def create_token(subject: Union[str, Any], token_type: str, expires_delta: Optional[timedelta] = None):
    currentTs = datetime.utcnow()
    if expires_delta:
        expire = currentTs + expires_delta
    if token_type == "access_token":
        expire = currentTs + timedelta(minutes=int(config_credentials["ACCESS_TOKEN_EXPIRE_MINUTES"]) * 60)
    if token_type == "refresh_token":
        expire = currentTs + timedelta(minutes=int(config_credentials["REFRESH_TOKEN_EXPIRE_MINUTES"]) * 60)

    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "token_type": str(token_type),
        "iss": config_credentials["PROJECT_NAME"],
        "iat": currentTs,
    }
    encoded_jwt = jwt.encode(to_encode, jwt_secret, algorithm=config_credentials["JWT_ALGORITHM"])
    return encoded_jwt


def get_password_hash(password: str):
    return pwd_context.hash(password)


def get_user_by_email_without_sess(email: str):
    db = SessionLocal()
    return (
        db.query(UserModel)
        .with_entities(UserModel.id, UserModel.name, UserModel.email, UserModel.is_active)
        .filter(UserModel.email == email)
        .first()
    )


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=ERR_SESSION_EXPIRED,
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, jwt_secret, algorithms=[config_credentials["JWT_ALGORITHM"]])
        redis_payload: str = payload.get("sub")
        token_type: str = payload.get("token_type")
        email = redisClient.get(redis_payload)

        if token_type == "refresh_token":
            raise credentials_exception
        if email is None:
            raise credentials_exception
        user = get_user_by_email_without_sess(email)
    except JWTError as e:
        print(e)
        raise credentials_exception
    if user is None:
        raise credentials_exception
    return user


def access_refresh_token(email: str):
    access_token_chardata = uuid.uuid4().hex
    refresh_token_chardata = uuid.uuid4().hex
    redisClient.setex(str(access_token_chardata), int(config_credentials["ACCESS_TOKEN_EXPIRE_MINUTES"]) * 60, email)
    redisClient.setex(str(refresh_token_chardata), int(config_credentials["REFRESH_TOKEN_EXPIRE_MINUTES"]) * 60, email)
    access_token = create_token(access_token_chardata, "access_token")
    refresh_token = create_token(refresh_token_chardata, "refresh_token")
    return access_token, refresh_token


def refresh_token(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=ERR_SESSION_EXPIRED,
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, jwt_secret, algorithms=[config_credentials["JWT_ALGORITHM"]])
        redis_payload: str = payload.get("sub")
        expire_time = payload.get("exp")
        token_type: str = payload.get("token_type")
        email = redisClient.get(redis_payload)
        if token_type == "access_token":
            raise credentials_exception
        redisClient.delete(redis_payload)

    except JWTError as e:
        print(e)
        raise credentials_exception
    if expire_time is None:
        raise credentials_exception
    if email is None:
        raise credentials_exception
    if datetime.utcnow() > datetime.fromtimestamp(expire_time):
        raise credentials_exception

    access_token, refresh_token = access_refresh_token(str(email))
    return {"access_token": access_token, "refresh_token": refresh_token}


async def get_current_active_user(current_user: UserFetch = Depends(get_current_user)):
    return current_user


async def logout_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Session Expired! Please login to continue",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, jwt_secret, algorithms=[config_credentials["JWT_ALGORITHM"]])
        redis_payload: str = payload.get("sub")
        redisClient.delete(redis_payload)
        if redis_payload is None:
            raise credentials_exception
    except Exception as e:
        print(e)
        raise credentials_exception
    return True


# Send User Verification Email
async def send_verification_email(email):
    try:
        tokenHex = uuid.uuid4().hex

        redisClient.setex("verify_" + str(tokenHex), 1800, email)
        redisClient.setex("verify_" + str(email), 119, "1")
        template_url = f"{config_credentials['BASE_URL']}/api/user/verifyAccount/?token={tokenHex}"
        message = MessageSchema(
            recipients=[email],
            subject="Email Verification - Algo Trading",
            template_body={"url": template_url},
        )

        conf = ConnectionConfig(
            MAIL_USERNAME=config_credentials["MAIL_USERNAME"],
            MAIL_PASSWORD=config_credentials["MAIL_PASSWORD"],
            MAIL_FROM=config_credentials["MAIL_FROM"],
            MAIL_PORT=config_credentials["MAIL_PORT"],
            MAIL_SERVER=config_credentials["MAIL_SERVER"],
            MAIL_TLS=config_credentials["MAIL_TLS"],
            MAIL_SSL=config_credentials["MAIL_SSL"],
            USE_CREDENTIALS=config_credentials["MAIL_USE_CREDENTIALS"],
            TEMPLATE_FOLDER=template_path,
        )

        fastmail = FastMail(conf)
        await fastmail.send_message(message=message, template_name="verify-email.html")
        return True
    except Exception:
        return False


# Send User Verification OTP
async def send_forgot_password_otp(email):
    try:
        digits = "0123456789"
        OTP = ""
        for i in range(6):
            OTP += digits[math.floor(random.random() * 10)]
        redisClient.setex("verify_otp_flag_" + str(email), 120, "1")
        redisClient.setex("verify_otp" + str(email), 300, OTP)

        message = MessageSchema(
            recipients=[email],
            subject="Reset Password - Algo Trading",
            template_body={"OTP": OTP},
        )

        conf = ConnectionConfig(
            MAIL_USERNAME=config_credentials["MAIL_USERNAME"],
            MAIL_PASSWORD=config_credentials["MAIL_PASSWORD"],
            MAIL_FROM=config_credentials["MAIL_FROM"],
            MAIL_PORT=config_credentials["MAIL_PORT"],
            MAIL_SERVER=config_credentials["MAIL_SERVER"],
            MAIL_TLS=config_credentials["MAIL_TLS"],
            MAIL_SSL=config_credentials["MAIL_SSL"],
            USE_CREDENTIALS=config_credentials["MAIL_USE_CREDENTIALS"],
            TEMPLATE_FOLDER=template_path,
        )

        fastmail = FastMail(conf)
        await fastmail.send_message(message=message, template_name="verify-otp.html")
        return True
    except Exception as e:
        print(e)
        return False
