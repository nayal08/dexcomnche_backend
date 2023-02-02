import traceback
from fastapi.encoders import jsonable_encoder
from ..database import get_db
from ..models import UserModel
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi import APIRouter, Depends, status, HTTPException
from ..schemas.user_schema import (
    UserSignup,
    UserSignupSuccess,
    UserLogin,
    UserFetch,
    UserOtp,
    UserData,
    UserResetPassword,
    UserChangePassword,
)
from dotenv import dotenv_values

from ..commons.dependencies import (
    jsonify_res,
    get_password_hash,
    send_verification_email,
    redisClient,
    get_current_active_user,
    logout_current_user,
    refresh_token,
    access_refresh_token,
    send_forgot_password_otp,
)
from ..commons.error_msg import (
    ERR_SIGNUP_EXISTS,
    ERR_SIGNUP,
    ERR_SIGNUP_VERIFICATION_EXPIRED,
    ERR_LOGIN,
    ERR_VERIFICATION_GENERATED,
    ERR_VERIFICATION_EXISTS,
    ERR_SIGNUP_INVALID_VERIFICATION,
    ERR_EMAIL_NOT_EXISTS,
    ERR_RESET_REQ_RAISED,
    ERR_SENDING_RESET_OTP,
    ERR_OTP_NOT_MATCHED,
    ERROR_OTP_EXPIRED,
    ERR_WRONG_PWD,
    ERR_SAME_PWD,
)
from ..commons.success_msg import (
    SUCCESS_MSG_SIGNUP,
    SUCCESS_MSG_LOGIN,
    SUCCESS_MSG_LOGGED_OUT,
    SUCCESS_MSG_RESEND_VERIFICATION,
    SUCCESS_MSG_SIGNUP_COMPLETE,
    SUCCESS_MSG_USER,
    SUCCESS_MSG_REFRESH_TOKEN_CREATED,
    SUCCESS_OTP_RESET_SENT,
    SUCCESS_RESET_PWD,
    SUCCESS_CHANGE_PWD,
)

config_credentials = dotenv_values(".env")

# Set Password Creation Context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter()


class UserActions:
    def __init__(self, db):
        self.db = db

    # Get user Data from email address
    def check_user_by_email(self, email: str):
        user_data = self.db.query(UserModel).filter(UserModel.email == email).first()
        if user_data:
            return True
        return False

    def get_user_by_email(self, email: str):
        user_data = self.db.query(UserModel).filter(UserModel.email == email).first()
        return user_data

    # Create a new user
    def db_signup_new_user(self, signup_data: UserSignup):
        try:
            user_add = UserModel(
                name=signup_data.name,
                email=signup_data.email,
                password=get_password_hash(signup_data.password),
                is_active=False,
            )
            self.db.add(user_add)
            self.db.commit()
            return signup_data
        except Exception:
            traceback.print_exc()
            return False

    # Update user profile after verification
    def complete_user_verification(self, email: str):
        try:
            update_user = {"is_active": True}
            self.db.query(UserModel).filter(UserModel.email == email).update(update_user, synchronize_session=False)
            self.db.commit()
            return True
        except Exception:
            traceback.print_exc()
            return False

    # Verify user password
    def verify_password(self, plain_password, hashed_password):
        return pwd_context.verify(plain_password, hashed_password)

    # Login User
    def db_login_user(self, login_data: UserLogin):
        try:
            check_login = self.get_user_by_email(login_data.email)

            if check_login:
                check_password = self.verify_password(login_data.password, check_login.password)

                if check_password:
                    print(check_login.email)
                    access_token, refresh_token = access_refresh_token(str(check_login.email))
                    return access_token, refresh_token, check_login.name, check_login.email, check_login.is_active
            return None, None, None, None, None
        except Exception:
            traceback.print_exc()
            return None


@router.post("/refresh-token")
def refresh(token: str = Depends(refresh_token)):
    return jsonify_res(
        access_token=token["access_token"],
        refresh_token=token["refresh_token"],
        message=SUCCESS_MSG_REFRESH_TOKEN_CREATED,
    )


@router.get("/user")
def test():
    data = {}
    data["test"] = "Hello User"
    return jsonify_res(data=data)


@router.post("/user/signup", response_model=UserSignupSuccess)
async def create_user(request: UserSignup, db_session: Session = Depends(get_db)):
    ucr = UserActions(db_session)
    user_exists = ucr.check_user_by_email(request.email)
    if user_exists:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_SIGNUP_EXISTS)
    create_user = ucr.db_signup_new_user(request)
    if create_user:
        # TODO: Define verification method
        # verification_complete = await send_verification_email(create_user.email)
        verification_complete = True
        if verification_complete:
            user_data = jsonable_encoder(create_user)
            return jsonify_res(success=True, email=user_data["email"], message=SUCCESS_MSG_SIGNUP)
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_SIGNUP)


@router.get("/user/verifyAccount")
async def verify_account(token: str, db_session: Session = Depends(get_db)):
    verifyToken = redisClient.get("verify_" + str(token))
    if verifyToken:
        ucr = UserActions(db_session)
        user_exists = ucr.get_user_by_email(verifyToken)
        if user_exists and user_exists.is_active is False:
            verify_user = ucr.complete_user_verification(verifyToken)
            if verify_user:
                redisClient.delete("verify_" + str(token))
                return jsonify_res(email=verifyToken, message=SUCCESS_MSG_SIGNUP_COMPLETE)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_SIGNUP_VERIFICATION_EXPIRED)
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_SIGNUP_INVALID_VERIFICATION)


@router.post("/user/login")
async def login_user(request: UserLogin, db_session: Session = Depends(get_db)):
    ucr = UserActions(db_session)
    access_token, refresh_token, user_name, user_email, is_active = ucr.db_login_user(request)
    print(access_token)
    if access_token and refresh_token:
        return jsonify_res(
            access_token=access_token,
            refresh_token=refresh_token,
            name=user_name,
            email=user_email,
            is_active=is_active,
            message=SUCCESS_MSG_LOGIN,
        )
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_LOGIN)


@router.get("/user/me", response_model=UserData)
async def show_user(db: Session = Depends(get_db), current_user: UserFetch = Depends(get_current_active_user)):
    user = db.query(UserModel).filter(UserModel.id == current_user.id).first()

    return jsonify_res(
        data={
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "is_active": user.is_active,
        },
        message=SUCCESS_MSG_USER,
    )


@router.put("/user/resend-verification")
async def resend_user_verification(
    current_user: UserFetch = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    userData = jsonable_encoder(current_user)
    if userData and userData["is_active"] is False:
        checkEmail = redisClient.get("verify_" + userData["email"])
        if checkEmail is None:
            verification_complete = await send_verification_email(userData["email"])
            if verification_complete:
                return jsonify_res(success=True, email=userData["email"], message=SUCCESS_MSG_RESEND_VERIFICATION)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_VERIFICATION_GENERATED)
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_VERIFICATION_EXISTS)


@router.post("/user/forgot-password")
async def forgotPassword(request: UserOtp, db_session: Session = Depends(get_db)):
    ucr = UserActions(db_session)
    user_exists = ucr.check_user_by_email(request.email)
    if user_exists:
        check_otp = redisClient.get("verify_otp_flag" + str(request.email))
        if check_otp:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_RESET_REQ_RAISED)
        otp_verification = await send_forgot_password_otp(request.email)
        if otp_verification:
            return jsonify_res(success=True, message=SUCCESS_OTP_RESET_SENT)
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_SENDING_RESET_OTP)

    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_EMAIL_NOT_EXISTS)


@router.post("/user/reset-password")
async def reset_password(request: UserResetPassword, db_session: Session = Depends(get_db)):
    verifyOtp = redisClient.get("verify_otp" + str(request.email))
    if verifyOtp:
        ucr = UserActions(db_session)
        user_exists = ucr.check_user_by_email(request.email)
        if user_exists:
            # user = (
            #     db_session.query(UserModel)
            #     .with_entities(UserModel.id, UserModel.email, UserModel.name, UserModel.password)
            #     .filter(UserModel.email == request.email)
            #     .first()
            # )
            # user_data = jsonable_encoder(user)
            # passwordexists = ucr.verify_password(request.password, user_data["password"])
            if verifyOtp == request.otp:
                # if passwordexists:
                #     raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_SAME_PWD)
                # else:
                password = get_password_hash(request.password)
                updatedata = {"password": password}
                db_session.query(UserModel).filter(UserModel.email == request.email).update(updatedata)
                db_session.commit()
                redisClient.delete("verify_otp" + str(request.email))
                return jsonify_res(success=True, message=SUCCESS_RESET_PWD)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_OTP_NOT_MATCHED)
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_OTP_NOT_MATCHED)
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERROR_OTP_EXPIRED)


@router.post("/user/change-password")
async def change_password(
    request: UserChangePassword,
    db: Session = Depends(get_db),
    current_user: UserFetch = Depends(get_current_active_user),
):
    user = (
        db.query(UserModel)
        .with_entities(UserModel.id, UserModel.email, UserModel.name, UserModel.password)
        .filter(UserModel.id == current_user.id, UserModel.email == current_user.email)
        .first()
    )
    user_data = jsonable_encoder(user)
    ucr = UserActions(db)
    user_exists = ucr.verify_password(request.current_password, user_data["password"])
    if user_exists:
        if request.new_password == request.current_password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_SAME_PWD)
        else:
            new_password = get_password_hash(request.new_password)
            updatedata = {"password": new_password}
            db.query(UserModel).filter(UserModel.id == current_user.id, UserModel.email == current_user.email).update(
                updatedata
            )
            db.commit()
            return jsonify_res(sucess=True, message=SUCCESS_CHANGE_PWD)
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERR_WRONG_PWD)


@router.delete("/user/logout")
async def logout_user(
    current_user: UserFetch = Depends(get_current_active_user),
    logout_user: bool = Depends(logout_current_user),
):
    try:
        if logout_user:
            return jsonify_res(success=True, message=SUCCESS_MSG_LOGGED_OUT)
    except Exception as e:
        print(e)
        return jsonify_res(success=False, message="Error Logging out!")
