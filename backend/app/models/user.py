from typing import Optional
from datetime import datetime
from sqlmodel import Field, SQLModel

class UserBase(SQLModel):
    username: str = Field(index=True)
    email: str = Field(index=True)
    is_active: bool = True
    is_superuser: bool = False

class User(UserBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str
    security_question: str = Field(default="")
    security_answer_hash: str = Field(default="")
    recovery_code_hash: Optional[str] = Field(default=None)
    recovery_code_expires_at: Optional[datetime] = Field(default=None)

class UserCreate(UserBase):
    password: str
    security_question: str
    security_answer: str

class UserRead(UserBase):
    id: int
    security_question: str

class UserUpdate(SQLModel):
    username: Optional[str] = None
    password: Optional[str] = None
    email: Optional[str] = None
    is_active: Optional[bool] = None
    security_question: Optional[str] = None
    security_answer: Optional[str] = None
