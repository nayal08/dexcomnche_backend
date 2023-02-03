from fastapi import APIRouter
from fastapi import Depends, status, HTTPException
from fastapi.encoders import jsonable_encoder
from ..commons.admin_dependencies import (
    jsonify_res,
    get_password_hash,
    redisClient,
    create_access_token,
    get_current_active_admin,
    get_current_admin,
    logout_current_admin,
)
from ..commons.error_msg import (
    ERR_SIGNUP_EXISTS,
    ERR_SIGNUP,
    ERR_LOGIN,
)
from ..commons.success_msg import (
    SUCCESS_MSG_SIGNUP,
    SUCCESS_MSG_LOGIN,
    SUCCESS_MSG_LOGGED_OUT,
)
from ..database import get_db
from ..schemas.user_schema import UserSignup, UserLogin, AdminFetch
from ..models import AdminModel
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import traceback
import uuid

# Set Password Creation Context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter()


class AdminActions:
    def __init__(self, db):
        self.db = db

    # Get admin Data from email address
    def check_admin_by_email(self, email: str):
        admin_data = self.db.query(AdminModel).filter(AdminModel.email == email).first()
        if admin_data:
            return True
        return False

    def get_admin_by_email(self, email: str):
        admin_data = self.db.query(AdminModel).filter(AdminModel.email == email).first()
        return admin_data

    def get_current_active_admin(current_admin: AdminFetch = Depends(get_current_admin)):
        if not current_admin.email_verified:
            raise HTTPException(status_code=400, detail="Inactive admin")
        return current_admin

    # Create a new admin
    def db_signup_new_admin(self, signup_data: UserSignup):
        try:
            admin_add = AdminModel(
                name=signup_data.name,
                email=signup_data.email,
                password=get_password_hash(signup_data.password),
                is_active=True,
            )
            self.db.add(admin_add)
            self.db.commit()
            return signup_data
        except Exception:
            traceback.print_exc()
            return False

    # Verify admin password
    def verify_password(self, plain_password, hashed_password):
        return pwd_context.verify(plain_password, hashed_password)

    # Login User
    def db_login_admin(self, login_data: UserLogin):
        try:
            check_login = self.get_admin_by_email(login_data.email)
            if check_login:
                check_password = self.verify_password(login_data.password, check_login.password)
                if check_password:
                    charData = uuid.uuid4().hex
                    redisClient.setex(str(charData), 86401, str(check_login.email))
                    access_token = create_access_token(charData)
                    return access_token, check_login.name, check_login.email
            return None, None, None
        except Exception:
            traceback.print_exc()
            return None


@router.get("/admin")
def test():
    data = {}
    data["test"] = "Hello Admin"
    return jsonify_res(data=data)


@router.post("/admin/create")
async def create_admin(request: UserSignup, db_session: Session = Depends(get_db)):
    ucr = AdminActions(db_session)
    admin_exists = ucr.check_admin_by_email(request.email)
    if admin_exists:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_SIGNUP_EXISTS)
    create_admin = ucr.db_signup_new_admin(request)
    if create_admin:
        admin_data = jsonable_encoder(create_admin)
        return jsonify_res(success=True, email=admin_data["email"], message=SUCCESS_MSG_SIGNUP)
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_SIGNUP)


@router.post("/admin/login")
async def login_admin(request: UserLogin, db_session: Session = Depends(get_db)):
    ucr = AdminActions(db_session)
    access_token, admin_name, admin_email = ucr.db_login_admin(request)
    if access_token:
        return jsonify_res(access_token=access_token, name=admin_name, email=admin_email, message=SUCCESS_MSG_LOGIN)
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_LOGIN)


@router.get("/admin/me")
async def read_admins_me(
    current_admin: AdminFetch = Depends(get_current_active_admin),
    db: Session = Depends(get_db),
):
    userData = jsonable_encoder(current_admin)
    del userData["id"]
    del userData["password"]
    return userData


@router.delete("/admin/logout")
async def logout_admin(
    current_admin: AdminFetch = Depends(get_current_active_admin),
    logout_admin: bool = Depends(logout_current_admin),
):
    try:
        if logout_admin:
            return jsonify_res(success=True, message=SUCCESS_MSG_LOGGED_OUT)
    except Exception as e:
        print(e)
        return jsonify_res(success=False, message="Error Logging out!")


