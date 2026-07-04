from typing import Any, List
from fastapi import APIRouter, Depends
from sqlmodel import Session, select
from sqlalchemy import func
from datetime import datetime, timedelta, timezone

from app.api import deps
from app.core.db import get_session
from app.models.user import User
from app.models.scan_history import ScanHistory, ScanHistoryCreate, ScanHistoryRead

router = APIRouter()

@router.get("/insights")
def get_user_insights(
    session: Session = Depends(get_session),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Retrieve insights/statistics for the current user.
    """
    # total scans
    total_scans = session.exec(
        select(func.count(ScanHistory.id))
        .where(ScanHistory.user_id == current_user.id)
    ).one_or_none() or 0
    
    # scan types
    scan_types = session.exec(
        select(ScanHistory.scan_type, func.count(ScanHistory.id))
        .where(ScanHistory.user_id == current_user.id)
        .group_by(ScanHistory.scan_type)
    ).all()
    
    by_type = [{"type": st, "count": c} for st, c in scan_types]
    
    # active days (last 7 days)
    now = datetime.utcnow()
    daily_data = []
    for i in range(7):
        date = (now - timedelta(days=6-i)).date()
        start_of_day = datetime(date.year, date.month, date.day)
        end_of_day = start_of_day + timedelta(days=1)
        count = session.exec(
            select(func.count(ScanHistory.id))
            .where(ScanHistory.user_id == current_user.id)
            .where(ScanHistory.created_at >= start_of_day)
            .where(ScanHistory.created_at < end_of_day)
        ).one_or_none() or 0
        daily_data.append({"date": date.isoformat(), "scans": count})
        
    return {
        "total_scans": total_scans,
        "by_type": by_type,
        "daily_last_7_days": daily_data
    }

@router.get("/", response_model=List[ScanHistoryRead])
def read_history(
    session: Session = Depends(get_session),
    current_user: User = Depends(deps.get_current_user),
    skip: int = 0,
    limit: int = 1000,
) -> Any:
    """
    Retrieve history for the current user.
    """
    statement = (
        select(ScanHistory)
        .where(ScanHistory.user_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .order_by(ScanHistory.created_at.desc())
    )
    history_items = session.exec(statement).all()
    
    # Convert to IST for display consistency with naive strings used elsewhere
    from datetime import timedelta, timezone
    ist = timezone(timedelta(hours=5, minutes=30))
    for item in history_items:
        if item.created_at:
             # Assume UTC if naive (which it usually is in DB), or use existing tz
             dt = item.created_at
             if dt.tzinfo is None:
                 dt = dt.replace(tzinfo=timezone.utc)
             # Convert to IST and strip tzinfo to make it naive
             # This forces Pydantic/Frontend to treat it as "Local" (which is now IST)
             item.created_at = dt.astimezone(ist).replace(tzinfo=None)
             
    return history_items

@router.post("/", response_model=ScanHistoryRead)
def create_history_item(
    *,
    session: Session = Depends(get_session),
    current_user: User = Depends(deps.get_current_user),
    item_in: ScanHistoryCreate,
) -> Any:
    """
    Create new history item.
    """
    history_item = ScanHistory.from_orm(item_in, update={"user_id": current_user.id})
    session.add(history_item)
    session.commit()
    session.refresh(history_item)
    return history_item

@router.delete("/{history_id}", response_model=ScanHistoryRead)
def delete_history_item(
    history_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Delete a history item.
    """
    history_item = session.get(ScanHistory, history_id)
    if not history_item:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="History item not found")
    if history_item.user_id != current_user.id:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Not enough permissions")
    
    session.delete(history_item)
    session.commit()
    return history_item

@router.delete("/", response_model=dict)
def delete_all_history(
    session: Session = Depends(get_session),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Delete all history items for current user.
    """
    statement = select(ScanHistory).where(ScanHistory.user_id == current_user.id)
    history_items = session.exec(statement).all()
    
    for item in history_items:
        session.delete(item)
    
    session.commit()
    return {"message": "All history deleted successfully"}
