"""Authentication routes."""
import uuid
from typing import Optional
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.core.database import get_db
from app.services import auth_service
from app.models.auth import User

router = APIRouter(prefix="/auth", tags=["auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

class UserCreate(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    email_verified: bool

    class Config:
        from_attributes = True

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = auth_service.decode_token(token)
    if payload is None:
        raise credentials_exception
    email: str = payload.get("email")
    if email is None:
        raise credentials_exception
    user = auth_service.get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception
    return user

def get_optional_user(token: Optional[str] = Depends(OAuth2PasswordBearer(tokenUrl="api/v1/auth/login", auto_error=False)), db: Session = Depends(get_db)) -> Optional[User]:
    if not token:
        return None
    try:
        return get_current_user(token, db)
    except HTTPException:
        return None

@router.post("/register", response_model=UserResponse)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    user = auth_service.get_user_by_email(db, email=user_in.email)
    if user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    user = auth_service.create_user(db, email=user_in.email, password=user_in.password)
    # Simulate email OTP
    print(f"\n[EMAIL OTP SIMULATION] Verification email sent to {user.email}")
    print("[EMAIL OTP SIMULATION] Please check the Next.js login popup to enter this logic.\n")
    return user

@router.post("/login", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = auth_service.get_user_by_email(db, email=form_data.username)
    if not user or not auth_service.verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = auth_service.create_access_token(data={"sub": str(user.id), "email": user.email})
    refresh_token = auth_service.create_refresh_token(data={"sub": str(user.id), "email": user.email})
    
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@router.get("/me", response_model=UserResponse)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user
