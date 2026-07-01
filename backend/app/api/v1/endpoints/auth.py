from datetime import datetime, timedelta
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Body, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from app.core import security
from app.core.config import settings
from app.core.db import get_session
from app.models.token import Token
from app.models.user import User, UserCreate, UserRead, UserUpdate
from app.models.otp import OTP
from app.core.email import send_otp_email
from app.api import deps
import random


class UserRegister(UserCreate):
    otp: str

router = APIRouter()

@router.post("/login/access-token", response_model=Token)
def login_access_token(
    session: Session = Depends(get_session), 
    form_data: OAuth2PasswordRequestForm = Depends()
) -> Any:
    statement = select(User).where(User.username == form_data.username)
    user = session.exec(statement).first()
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    elif not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return {
        "access_token": security.create_access_token(
            user.id, expires_delta=access_token_expires
        ),
        "token_type": "bearer",
    }

@router.get("/me", response_model=UserRead)
def get_current_user_data(
    current_user: User = Depends(deps.get_current_user)
) -> Any:
    """Get current authenticated user's data"""
    return current_user

@router.post("/register", response_model=UserRead)
def register_user(
    *,
    session: Session = Depends(get_session),
    user_in: UserRegister,
) -> Any:
    # Extract OTP
    otp = user_in.otp
    # Verify OTP
    # For registration, we might use the email from user_in to verify
    statement = select(OTP).where(
        OTP.email == user_in.email, 
        OTP.purpose == "register"
    ).order_by(OTP.created_at.desc())
    otp_record = session.exec(statement).first()
    
    if not otp_record or not security.verify_password(otp, otp_record.otp_hash):
         raise HTTPException(status_code=400, detail="Invalid OTP")
         
    if datetime.utcnow() > otp_record.expires_at:
         raise HTTPException(status_code=400, detail="OTP expired")

    print(f"DEBUG: Registering user {user_in.username}")
    print(f"DEBUG: Data received: {user_in}")
    
    statement = select(User).where(User.username == user_in.username)
    user = session.exec(statement).first()
    if user:
        print("DEBUG: User already exists")
        raise HTTPException(
            status_code=400,
            detail="The user with this username already exists in the system",
        )
    
    # Exclude fields that are not in the User model (like security_answer)
    try:
        user_data = user_in.dict(exclude={"password", "security_answer", "otp"})
        user = User(**user_data)
        
        user.hashed_password = security.get_password_hash(user_in.password)
        # Hash the security answer for privacy (normalized)
        normalized_answer = user_in.security_answer.strip().lower()
        user.security_answer_hash = security.get_password_hash(normalized_answer)
        
        session.add(user)
        session.commit()
        session.refresh(user)
        print(f"DEBUG: User {user.username} created successfully with ID {user.id}")
        return user
    except Exception as e:
        print(f"DEBUG: Database error during registration: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@router.post("/security-question", response_model=Any)
def get_security_question(
    *,
    session: Session = Depends(get_session),
    username: str = Body(..., embed=True),
) -> Any:
    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )
    return {"security_question": user.security_question}

@router.post("/recover-password", response_model=Any)
def recover_password(
    *,
    session: Session = Depends(get_session),
    username: str = Body(...),
    security_answer: str = Body(...),
    new_password: str = Body(...),
) -> Any:
    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()
    print(f"DEBUG: Recovering password for {username}")
    if not user:
        print("DEBUG: User not found")
        raise HTTPException(status_code=404, detail="User not found")
    
    normalized_input = security_answer.strip().lower()
    print(f"DEBUG: Stored hash prefix: {user.security_answer_hash[:10] if user.security_answer_hash else 'NONE'}")
    print(f"DEBUG: Incoming answer: '{security_answer}'")
    print(f"DEBUG: Normalized input: '{normalized_input}'")
    
    is_valid = security.verify_password(normalized_input, user.security_answer_hash)
    print(f"DEBUG: Verification result: {is_valid}")

    if not is_valid:
        raise HTTPException(status_code=400, detail="Incorrect security answer")
        
    user.hashed_password = security.get_password_hash(new_password)
    session.add(user)
    session.commit()
    return {"message": "Password reset successfully"}

@router.post("/verify-otp", response_model=Any)
def verify_otp_only(
    *,
    session: Session = Depends(get_session),
    email: str = Body(..., embed=True),
    otp: str = Body(..., embed=True),
    purpose: str = Body(..., embed=True),
) -> Any:
    statement = select(OTP).where(
        OTP.email == email, 
        OTP.purpose == purpose
    ).order_by(OTP.created_at.desc())
    otp_record = session.exec(statement).first()
    
    if not otp_record or not security.verify_password(otp, otp_record.otp_hash):
         raise HTTPException(status_code=400, detail="Invalid OTP")
         
    if datetime.utcnow() > otp_record.expires_at:
         raise HTTPException(status_code=400, detail="OTP expired")
         
    return {"message": "OTP verified successfully"}

@router.post("/change-password", response_model=Any)
def change_password(
    *,
    session: Session = Depends(get_session),
    current_user: User = Depends(deps.get_current_user),
    new_password: str = Body(...),
    otp: str = Body(...),
) -> Any:
    # OTP based authentication for password change
    # We no longer require old_password since OTP proves identity/ownership
        
    # Verify OTP
    statement = select(OTP).where(
        OTP.email == current_user.email, 
        OTP.purpose == 'change_password'
    ).order_by(OTP.created_at.desc())
    otp_record = session.exec(statement).first()
    
    if not otp_record or not security.verify_password(otp, otp_record.otp_hash):
         raise HTTPException(status_code=400, detail="Invalid OTP")
         
    if datetime.utcnow() > otp_record.expires_at:
         raise HTTPException(status_code=400, detail="OTP expired")
         
    current_user.hashed_password = security.get_password_hash(new_password)
    session.add(current_user)
    session.commit()
    return {"message": "Password updated successfully"}

@router.post("/identify", response_model=Any)
def identify_user(
    *,
    session: Session = Depends(get_session),
    identifier: str = Body(..., embed=True),
) -> Any:
    # Try by username
    statement = select(User).where(User.username == identifier)
    user = session.exec(statement).first()
    
    # Try by email if not found
    if not user:
        statement = select(User).where(User.email == identifier)
        user = session.exec(statement).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    return {
        "username": user.username,
        "email": user.email, # Mask logic could be here
        "security_question": user.security_question,
        "has_security_question": bool(user.security_question),
        "params": ["question", "otp"] # Available methods
    }

from fastapi import APIRouter, Depends, HTTPException, status, Body, BackgroundTasks

@router.post("/request-otp", response_model=Any)
def request_otp(
    *,
    session: Session = Depends(get_session),
    email: str = Body(..., embed=True),
    purpose: str = Body(..., embed=True), # register, reset, change_password
) -> Any:
    user_statement = select(User).where(User.email == email)
    user = session.exec(user_statement).first()

    if purpose == "register":
        if user:
            raise HTTPException(status_code=400, detail="Email already registered")
    elif purpose in ["reset", "change_password"]:
        if not user:
             # Security: Don't reveal user existence? 
             # For now, let's reveal it to help valid users or keep consistent behavior.
             # Ideally we should just say "If email exists, OTP sent".
             # But for simplicity in this project:
             raise HTTPException(status_code=404, detail="User not found with this email")
    else:
        raise HTTPException(status_code=400, detail="Invalid purpose")
        
    # Generate OTP
    code = f"{random.randint(0, 999999):06d}"
    print(f" [OTP] {purpose} code for {email}: {code}")
    
    # Store OTP
    otp_hash = security.get_password_hash(code)
    db_otp = OTP(
        email=email,
        otp_hash=otp_hash,
        purpose=purpose,
        expires_at=datetime.utcnow() + timedelta(minutes=10)
    )
    session.add(db_otp)
    session.commit()
    
    # Send email — run synchronously so we can catch errors and report them
    try:
        send_otp_email(email, code, purpose)
    except Exception as e:
        print(f"[OTP] Email delivery failed for {email}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"OTP generated but email delivery failed: {str(e)}. Check server SMTP configuration."
        )
    
    return {"message": "OTP sent to email"}

@router.post("/recover-with-otp", response_model=Any)
def recover_with_otp(
    *,
    session: Session = Depends(get_session),
    email: str = Body(...),
    otp: str = Body(...),
    new_password: str = Body(...),
) -> Any:
    # Changed input from username to email
    statement = select(User).where(User.email == email)
    user = session.exec(statement).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Verify OTP
    otp_statement = select(OTP).where(
        OTP.email == email, 
        OTP.purpose == 'reset'
    ).order_by(OTP.created_at.desc())
    otp_record = session.exec(otp_statement).first()
    
    if not otp_record or not security.verify_password(otp, otp_record.otp_hash):
         raise HTTPException(status_code=400, detail="Invalid OTP")

    if datetime.utcnow() > otp_record.expires_at:
         raise HTTPException(status_code=400, detail="OTP expired")

    # Reset password
    user.hashed_password = security.get_password_hash(new_password)
    
    session.add(user)
    session.commit()
    return {"message": "Password reset successfully"}
