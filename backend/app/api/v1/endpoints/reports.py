import csv
import io
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlmodel import Session, select
from app.api import deps
from app.models.user import User
from app.models.scan_history import ScanHistory
from app.core.db import get_session

router = APIRouter()

@router.post("/export/history")
def export_history(
    current_user: User = Depends(deps.get_current_user),
    session: Session = Depends(get_session)
):
    # Query scan history for current user
    statement = select(ScanHistory).where(ScanHistory.user_id == current_user.id).order_by(ScanHistory.created_at.desc())
    history = session.exec(statement).all()
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Scan Type", "Target", "Result", "Date"])
    
    for scan in history:
        writer.writerow([scan.id, scan.scan_type, scan.target, scan.result, scan.created_at])
        
    output.seek(0)
    
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=scan_history.csv"}
    )
