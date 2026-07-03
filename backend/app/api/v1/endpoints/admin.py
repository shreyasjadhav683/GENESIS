"""
Admin endpoints — superuser only.
Provides user management: list, activate/deactivate, delete, promote to superuser.
All routes require is_superuser=True on the calling account.
"""
from datetime import datetime
from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlmodel import Session, select

from app.api import deps
from app.core.db import get_session
from app.models.user import User, UserRead

router = APIRouter()


def require_superuser(current_user: User = Depends(deps.get_current_user)) -> User:
    """Dependency: raises 403 if caller is not a superuser."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required.",
        )
    return current_user


# ── List all users ────────────────────────────────────────────────────────────

@router.get("/users", response_model=List[dict])
def list_users(
    session: Session = Depends(get_session),
    _admin: User = Depends(require_superuser),
) -> Any:
    """Return all registered users with safe fields (no password hashes)."""
    users = session.exec(select(User)).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "is_active": u.is_active,
            "is_superuser": u.is_superuser,
            "security_question": u.security_question,
        }
        for u in users
    ]


# ── Toggle active status ──────────────────────────────────────────────────────

@router.patch("/users/{user_id}/toggle-active", response_model=dict)
def toggle_active(
    user_id: int,
    session: Session = Depends(get_session),
    admin: User = Depends(require_superuser),
) -> Any:
    """Activate or deactivate a user account."""
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    user.is_active = not user.is_active
    session.add(user)
    session.commit()
    session.refresh(user)
    return {"id": user.id, "username": user.username, "is_active": user.is_active}


# ── Toggle superuser status ───────────────────────────────────────────────────

@router.patch("/users/{user_id}/toggle-superuser", response_model=dict)
def toggle_superuser(
    user_id: int,
    session: Session = Depends(get_session),
    admin: User = Depends(require_superuser),
) -> Any:
    """Promote or demote a user to/from superuser."""
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot change your own admin status")
    user.is_superuser = not user.is_superuser
    session.add(user)
    session.commit()
    session.refresh(user)
    return {"id": user.id, "username": user.username, "is_superuser": user.is_superuser}


# ── Delete user ───────────────────────────────────────────────────────────────

@router.delete("/users/{user_id}", response_model=dict)
def delete_user(
    user_id: int,
    session: Session = Depends(get_session),
    admin: User = Depends(require_superuser),
) -> Any:
    """Permanently delete a user account."""
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    session.delete(user)
    session.commit()
    return {"message": f"User '{user.username}' deleted successfully"}


# ── Stats overview ────────────────────────────────────────────────────────────

@router.get("/stats", response_model=dict)
def admin_stats(
    session: Session = Depends(get_session),
    _admin: User = Depends(require_superuser),
) -> Any:
    """Quick stats for the admin dashboard."""
    users = session.exec(select(User)).all()
    total = len(users)
    active = sum(1 for u in users if u.is_active)
    admins = sum(1 for u in users if u.is_superuser)
    return {
        "total_users": total,
        "active_users": active,
        "inactive_users": total - active,
        "admin_users": admins,
    }
