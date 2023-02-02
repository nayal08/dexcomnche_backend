import requests
from fastapi import APIRouter, HTTPException, Depends, status
from ..schemas.user_schema import UserFetch
from ..database import SessionLocal
from ..models import AdminModel
from passlib.context import CryptContext
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from jose import jwt, JWTError
import redis
import os
from ..commons.error_msg import ERR_SESSION_EXPIRED

# from ..models import *
import traceback
from typing import Any, Optional, Union
import os.path
from pathlib import Path
from dotenv import dotenv_values

config_credentials = dotenv_values(".env")
# print(config_credentials)

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


def create_access_token(subject: Union[str, Any], expires_delta: Optional[timedelta] = None):
    currentTs = datetime.utcnow()
    if expires_delta:
        expire = currentTs + expires_delta
    else:
        expire = currentTs + timedelta(minutes=int(config_credentials["ACCESS_TOKEN_EXPIRE_MINUTES"]))
    to_encode = {"exp": expire, "sub": str(subject), "iss": config_credentials["PROJECT_NAME"], "iat": currentTs}
    encoded_jwt = jwt.encode(to_encode, jwt_secret, algorithm=config_credentials["JWT_ALGORITHM"])
    return encoded_jwt


def get_password_hash(password: str):
    return pwd_context.hash(password)


def get_admin_by_email_without_sess(email: str):
    db = SessionLocal()
    return (
        db.query(AdminModel)
        .with_entities(AdminModel.id, AdminModel.name, AdminModel.email, AdminModel.password, AdminModel.is_active)
        .filter(AdminModel.email == email)
        .first()
    )


def get_current_admin(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=ERR_SESSION_EXPIRED,
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, jwt_secret, algorithms=[config_credentials["JWT_ALGORITHM"]])
        redisPayload: str = payload.get("sub")
        email = redisClient.get(redisPayload)

        if email is None:
            raise credentials_exception
        user = get_admin_by_email_without_sess(email)
    except JWTError as e:
        print(e)
        raise credentials_exception
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_admin(current_admin: UserFetch = Depends(get_current_admin)):
    # if not current_admin.is_active:
    #     raise HTTPException(status_code=400, detail="Inactive user")
    return current_admin


async def logout_current_admin(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Session Expired! Please login to continue",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, jwt_secret, algorithms=[config_credentials["JWT_ALGORITHM"]])
        redisPayload: str = payload.get("sub")
        redisClient.delete(redisPayload)
        if redisPayload is None:
            raise credentials_exception
    except Exception as e:
        print(e)
        raise credentials_exception
    return True
