from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api import deps

from app.models.user import User
from app.core.file_integrity_service import file_integrity_service
from pydantic import BaseModel
import os

router = APIRouter()

class PathRequest(BaseModel):
    path: str

@router.post("/baseline")
def create_baseline(
    request: PathRequest,
    current_user: User = Depends(deps.get_current_user),
):
    """
    Creates a new baseline snapshot for the specified file.
    """
    if not os.path.exists(request.path):
        raise HTTPException(status_code=400, detail="File does not exist on the server.")
    if not os.path.isfile(request.path):
         raise HTTPException(status_code=400, detail="Path must be a file, not a directory.")

    try:
        baseline = file_integrity_service.create_baseline(request.path)
        return {"message": "Baseline created successfully", "details": baseline}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan")
def scan_integrity(
    request: PathRequest,
    current_user: User = Depends(deps.get_current_user),
    session: Session = Depends(deps.get_session),
):
    """
    Verifies the integrity of the file against the last baseline.
    """
    if not os.path.exists(request.path):
        raise HTTPException(status_code=400, detail="File does not exist on the server.")
    if not os.path.isfile(request.path):
         raise HTTPException(status_code=400, detail="Path must be a file, not a directory.")

    try:
        result = file_integrity_service.verify_integrity(request.path)
        
        # Save to history
        import json
        from app.models.scan_history import ScanHistory
        
        scan = ScanHistory(
            user_id=current_user.id,
            scan_type="FILE_INTEGRITY",
            target=os.path.basename(request.path), 
            result=json.dumps(result, default=str)
        )
        session.add(scan)
        session.commit()
        
        return result
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="No baseline found. Please create a baseline first.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/browse")
def browse_directory(
    path: str = "",
    current_user: User = Depends(deps.get_current_user),
):
    """
    Lists directories and files in the specified path. 
    If path is empty, lists available drives (Windows) or root (Linux).
    """
    try:
        if not path:
            # List Drives on Windows
            if os.name == 'nt':
                drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:")]
                return {"type": "drives", "contents": drives}
            else:
                # Unix root
                return {"type": "dir", "path": "/", "contents": ["/"]}
        
        # Security check (basic)
        if ".." in path:
             raise HTTPException(status_code=400, detail="Path traversal not allowed")

        if not os.path.exists(path) or not os.path.isdir(path):
            raise HTTPException(status_code=400, detail="Invalid directory path")

        items = []
        with os.scandir(path) as it:
            for entry in it:
                if not entry.name.startswith('.'):
                    if entry.is_dir():
                         items.append(f"{entry.name}/")
                    else:
                         items.append(entry.name)
        
        return {"type": "dir", "path": path, "contents": sorted(items)}

    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")
    except Exception as e:
         raise HTTPException(status_code=500, detail=str(e))
