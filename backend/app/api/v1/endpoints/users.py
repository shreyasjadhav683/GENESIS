from typing import Any
from fastapi import APIRouter, Body, Depends, HTTPException
from sqlmodel import Session, select

from app.api import deps
from app.core import security
from app.core.db import get_session
from app.models.user import User, UserRead, UserUpdate

router = APIRouter()

@router.put("/me", response_model=UserRead)
def update_user_me(
    *,
    session: Session = Depends(get_session),
    user_in: UserUpdate,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Update own user.
    """
    if user_in.email and user_in.email != current_user.email:
        statement = select(User).where(User.email == user_in.email)
        existing_user = session.exec(statement).first()
        if existing_user:
            raise HTTPException(
                status_code=400, detail="This email is already registered."
            )
            
    if user_in.username and user_in.username != current_user.username:
        statement = select(User).where(User.username == user_in.username)
        existing_user = session.exec(statement).first()
        if existing_user:
            raise HTTPException(
                status_code=400, detail="This username is already taken."
            )

    user_data = user_in.dict(exclude_unset=True)
    
    # Handle security answer hashing
    if "security_answer" in user_data and user_data["security_answer"]:
        normalized_answer = user_data["security_answer"].strip().lower()
        user_data["security_answer_hash"] = security.get_password_hash(normalized_answer)
        del user_data["security_answer"]
        
    # Handle security question
    if "security_question" in user_data:
        # If security question is being updated, ensure answer is also provided or already exists?
        # Ideally, we should require the answer if the question is changing, but UserUpdate makes fields optional.
        # For now, we trust the frontend to send both if changing them.
        pass

    # Basic fields
    current_user.sqlmodel_update(user_data)
    
    session.add(current_user)
    session.commit()
    session.refresh(current_user)
    return current_user
