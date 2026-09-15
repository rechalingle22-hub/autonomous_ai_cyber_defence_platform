# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Authentication schemas."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from datetime import datetime
from typing import Optional  # type: ignore
from pydantic import BaseModel, EmailStr, Field, ConfigDict  # type: ignore

try:
    from ..models.user import UserRole  # type: ignore
except (ImportError, ValueError):
    from backend.app.models.user import UserRole  # type: ignore



class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    username: str
    role: UserRole


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[UserRole] = None


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(..., min_length=8)
    role: UserRole = UserRole.ANALYST


class LoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    email: EmailStr
    role: UserRole
    is_active: bool
    created_at: datetime
