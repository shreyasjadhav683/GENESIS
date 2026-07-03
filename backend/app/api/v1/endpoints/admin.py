"""
Admin endpoints — superuser only.
Provides a dedicated admin login + full user management.
All management routes require is_superuser=True on the calling account.
"""
from datetime import datetime, timedelta
from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, status, Body, BackgroundTasks
from sqlmodel import Session, select
import random

from app.api import deps
from app.core import security
from app.core.config import settings
from app.core.db import get_session
from app.core.email import send_otp_email
from app.models.user import User, UserUpdate
from app.models.otp import OTP
from app.models.scan_history import ScanHistory
from app.models.chat import Chat, Message

router = APIRouter()


# ── Admin Login ───────────────────────────────────────────────────────────────

@router.post("/login/init", response_model=dict)
def admin_login_init(
    *,
    session: Session = Depends(get_session),
    background_tasks: BackgroundTasks,
    username: str = Body(...),
    password: str = Body(...),
) -> Any:
    """
    Step 1: Admin login. Verify credentials and send OTP.
    """
    user = session.exec(select(User).where(User.username == username)).first()
    if not user:
        user = session.exec(select(User).where(User.email == username)).first()

    if not user or not security.verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is inactive")

    if not user.is_superuser:
        raise HTTPException(status_code=403, detail="Access denied. Admin privileges required.")

    otp = str(random.randint(100000, 999999))
    otp_hash = security.get_password_hash(otp)
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    otp_record = OTP(
        email=user.email,
        otp_hash=otp_hash,
        purpose="admin_login",
        expires_at=expires_at
    )
    session.add(otp_record)
    session.commit()
    
    background_tasks.add_task(send_otp_email, user.email, otp, "admin_login")
    
    return {"message": "OTP sent to your email", "email": user.email}


@router.post("/login/verify", response_model=dict)
def admin_login_verify(
    *,
    session: Session = Depends(get_session),
    username: str = Body(...),
    password: str = Body(...),
    otp: str = Body(...),
) -> Any:
    """
    Step 2: Admin login. Verify OTP and issue JWT.
    """
    user = session.exec(select(User).where(User.username == username)).first()
    if not user:
        user = session.exec(select(User).where(User.email == username)).first()

    if not user or not security.verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_superuser:
        raise HTTPException(status_code=403, detail="Access denied.")

    otp_stmt = select(OTP).where(
        OTP.email == user.email, 
        OTP.purpose == "admin_login"
    ).order_by(OTP.created_at.desc())
    otp_record = session.exec(otp_stmt).first()
    
    if not otp_record or not security.verify_password(otp, otp_record.otp_hash):
         raise HTTPException(status_code=401, detail="Invalid OTP")
         
    if datetime.utcnow() > otp_record.expires_at:
         raise HTTPException(status_code=401, detail="OTP expired")

    token = security.create_access_token(
        user.id, expires_delta=timedelta(hours=8)
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "admin": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
        },
    }


# ── Superuser guard ───────────────────────────────────────────────────────────

def require_superuser(current_user: User = Depends(deps.get_current_user)) -> User:
    """Dependency: raises 403 if caller is not a superuser."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required.",
        )
    return current_user


# ── Update self (Admin profile) ───────────────────────────────────────────────

@router.patch("/me", response_model=dict)
def update_admin_me(
    *,
    session: Session = Depends(get_session),
    admin: User = Depends(require_superuser),
    user_in: UserUpdate,
) -> Any:
    """Update admin's own profile."""
    # Check if username or email is already taken by someone else
    if user_in.username:
        existing_username = session.exec(select(User).where(User.username == user_in.username)).first()
        if existing_username and existing_username.id != admin.id:
            raise HTTPException(status_code=400, detail="Username already exists")
        admin.username = user_in.username

    if user_in.email:
        existing_email = session.exec(select(User).where(User.email == user_in.email)).first()
        if existing_email and existing_email.id != admin.id:
            raise HTTPException(status_code=400, detail="Email already registered")
        admin.email = user_in.email

    if user_in.password:
        admin.hashed_password = security.get_password_hash(user_in.password)

    session.add(admin)
    session.commit()
    session.refresh(admin)

    return {
        "id": admin.id,
        "username": admin.username,
        "email": admin.email,
        "message": "Profile updated successfully"
    }


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

@router.get("/users/{user_id}", response_model=dict)
def read_user(
    user_id: int,
    session: Session = Depends(get_session),
    admin: User = Depends(require_superuser),
) -> Any:
    user = session.exec(select(User).where(User.id == user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_active": user.is_active,
        "is_superuser": user.is_superuser,
        "created_at": getattr(user, "created_at", None),
    }

@router.get("/users/{user_id}/details", response_model=dict)
def read_user_details(
    user_id: int,
    session: Session = Depends(get_session),
    admin: User = Depends(require_superuser),
) -> Any:
    """
    Get full details for a specific user: basic info, scans, chats, and OTPs.
    """
    user = session.exec(select(User).where(User.id == user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    scans = session.exec(
        select(ScanHistory)
        .where(ScanHistory.user_id == user_id)
        .order_by(ScanHistory.created_at.desc())
    ).all()
    
    chats = session.exec(
        select(Chat)
        .where(Chat.user_id == user_id)
        .order_by(Chat.created_at.desc())
    ).all()
    
    otps = session.exec(
        select(OTP)
        .where(OTP.email == user.email)
        .order_by(OTP.created_at.desc())
    ).all()

    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active,
            "is_superuser": user.is_superuser,
            "created_at": getattr(user, "created_at", None),
        },
        "scans": [
            {
                "id": s.id,
                "scan_type": s.scan_type,
                "target": s.target,
                "result": s.result,
                "created_at": s.created_at,
            } for s in scans
        ],
        "chats": [
            {
                "id": c.id,
                "title": c.title,
                "created_at": c.created_at,
            } for c in chats
        ],
        "otps": [
            {
                "id": o.id,
                "purpose": o.purpose,
                "expires_at": o.expires_at,
                "created_at": o.created_at,
            } for o in otps
        ],
    }

# ── Detailed Logs for Insights ────────────────────────────────────────────────

@router.get("/scans", response_model=list)
def get_scans(
    scan_type: str = None,
    user_id: int = None,
    date: str = None,
    today: bool = False,
    session: Session = Depends(get_session),
    admin: User = Depends(require_superuser),
) -> Any:
    """Get detailed scan logs, optionally filtered."""
    from datetime import datetime
    query = select(ScanHistory, User.username).join(User, ScanHistory.user_id == User.id, isouter=True)
    
    if scan_type:
        query = query.where(ScanHistory.scan_type == scan_type)
    if user_id:
        query = query.where(ScanHistory.user_id == user_id)
        
    results = session.exec(query.order_by(ScanHistory.created_at.desc())).all()
    
    now = datetime.utcnow()
    filtered_results = []
    for scan, username in results:
        # Filter by date string (YYYY-MM-DD)
        if date and scan.created_at.strftime("%Y-%m-%d") != date:
            continue
        if today and scan.created_at.strftime("%Y-%m-%d") != now.strftime("%Y-%m-%d"):
            continue
        filtered_results.append({
            "id": scan.id,
            "scan_type": scan.scan_type,
            "target": scan.target,
            "result": scan.result,
            "created_at": scan.created_at,
            "user_id": scan.user_id,
            "username": username or f"Deleted User (ID: {scan.user_id})"
        })
        
    return filtered_results

@router.get("/otps", response_model=list)
def get_otps(
    purpose: str = None,
    date: str = None,
    last24h: bool = False,
    session: Session = Depends(get_session),
    admin: User = Depends(require_superuser),
) -> Any:
    """Get detailed OTP logs, optionally filtered."""
    from datetime import datetime, timedelta
    query = select(OTP).order_by(OTP.created_at.desc())
    
    if purpose:
        query = query.where(OTP.purpose == purpose)
        
    results = session.exec(query).all()
    
    now = datetime.utcnow()
    filtered_results = []
    for otp in results:
        if date and otp.created_at.strftime("%Y-%m-%d") != date:
            continue
        if last24h and (now - otp.created_at).total_seconds() >= 86400:
            continue
        filtered_results.append({
            "id": otp.id,
            "email": otp.email,
            "purpose": otp.purpose,
            "created_at": otp.created_at,
            "expires_at": otp.expires_at
        })
        
    return filtered_results


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


# ── Insights ──────────────────────────────────────────────────────────────────

@router.get("/insights", response_model=dict)
def admin_insights(
    session: Session = Depends(get_session),
    _admin: User = Depends(require_superuser),
) -> Any:
    """
    Rich analytics for the admin dashboard:
    - Scan stats (total, by type, top users)
    - OTP stats (total, by purpose)
    - Daily activity for last 7 days
    - Security alerts (inactive accounts, OTP spam attempts)
    """
    from app.models.scan_history import ScanHistory
    from app.models.otp import OTP
    from collections import Counter, defaultdict
    from datetime import datetime, timedelta

    now = datetime.utcnow()

    # ── Users ──────────────────────────────────────────────────────────────
    users = session.exec(select(User)).all()
    user_map = {u.id: u.username for u in users}

    # ── Scans ──────────────────────────────────────────────────────────────
    scans = session.exec(select(ScanHistory)).all()
    total_scans = len(scans)

    scan_type_counter: Counter = Counter()
    user_scan_counter: Counter = Counter()
    daily_scans: dict = defaultdict(int)

    for sc in scans:
        scan_type_counter[sc.scan_type] += 1
        user_scan_counter[sc.user_id] += 1
        day = sc.created_at.strftime("%Y-%m-%d") if sc.created_at else "unknown"
        daily_scans[day] += 1

    # Top 5 scan types
    top_scan_types = [
        {"type": t, "count": c}
        for t, c in scan_type_counter.most_common(10)
    ]

    # Top 5 users by scan count
    top_scanners = [
        {"user_id": uid, "username": user_map.get(uid, f"user#{uid}"), "scans": cnt}
        for uid, cnt in user_scan_counter.most_common(5)
    ]

    # Last 7 days daily activity
    last7 = []
    for i in range(6, -1, -1):
        day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        last7.append({"date": day, "scans": daily_scans.get(day, 0)})

    # ── OTPs ───────────────────────────────────────────────────────────────
    otps = session.exec(select(OTP)).all()
    total_otps = len(otps)
    otp_purpose_counter: Counter = Counter(o.purpose for o in otps)
    otp_by_purpose = [
        {"purpose": p, "count": c}
        for p, c in otp_purpose_counter.most_common()
    ]

    # OTPs in last 24h (possible brute-force / spam signal)
    otps_24h = sum(
        1 for o in otps
        if o.created_at and (now - o.created_at).total_seconds() < 86400
    )

    # Email domains of registered users
    domain_counter: Counter = Counter()
    for u in users:
        if "@" in u.email:
            domain_counter[u.email.split("@")[1].lower()] += 1
    top_domains = [
        {"domain": d, "count": c}
        for d, c in domain_counter.most_common(5)
    ]

    # ── Security signals ────────────────────────────────────────────────────
    inactive_users = [
        {"id": u.id, "username": u.username, "email": u.email}
        for u in users if not u.is_active
    ]

    # Users with no scans
    users_with_scans = set(user_scan_counter.keys())
    dormant_users = [
        {"id": u.id, "username": u.username}
        for u in users
        if u.id not in users_with_scans and not u.is_superuser
    ]

    return {
        "generated_at": now.isoformat(),
        "scans": {
            "total": total_scans,
            "by_type": top_scan_types,
            "top_scanners": top_scanners,
            "daily_last_7_days": last7,
            "scans_today": daily_scans.get(now.strftime("%Y-%m-%d"), 0),
        },
        "otps": {
            "total": total_otps,
            "last_24h": otps_24h,
            "by_purpose": otp_by_purpose,
        },
        "users": {
            "total": len(users),
            "active": sum(1 for u in users if u.is_active),
            "inactive": inactive_users,
            "dormant": dormant_users,
            "top_email_domains": top_domains,
        },
        "security": {
            "otp_requests_24h": otps_24h,
            "high_otp_volume": otps_24h > 20,
            "inactive_accounts": len(inactive_users),
            "dormant_accounts": len(dormant_users),
        },
    }
