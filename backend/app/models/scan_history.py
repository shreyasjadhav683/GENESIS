from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel

class ScanHistoryBase(SQLModel):
    scan_type: str
    target: str
    result: str  # Stored as JSON string to be flexible
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ScanHistory(ScanHistoryBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")

class ScanHistoryCreate(ScanHistoryBase):
    pass

class ScanHistoryRead(ScanHistoryBase):
    id: int
    user_id: int
