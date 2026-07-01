from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel

class OTP(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True)
    otp_hash: str
    purpose: str  # 'register', 'reset', 'change_password'
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)
