# type: ignore
# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false
"""Authentication API router: Login, registration, and user profile."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from datetime import timedelta
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config.settings import settings
from backend.app.database.session import get_db
from backend.app.models.user import User, UserRole
from backend.app.schemas.auth import (
    Token,
    UserCreate,
    UserResponse,
    LoginRequest,
)
from backend.app.auth.security import (
    verify_password,
    get_password_hash,
    create_access_token,
)
from backend.app.auth.rbac import get_current_user
from backend.app.audit.service import audit_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_in: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Registers a new platform user."""
    # Check if username or email already exists
    existing_user = await db.execute(
        select(User).where((User.username == user_in.username) | (User.email == user_in.email))
    )
    if existing_user.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email is already registered",
        )

    user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        role=user_in.role,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    role_val = getattr(user.role, "value", str(user.role))
    await audit_service.log_event(
        db=db,
        action="USER_REGISTERED",
        resource_type="USER",
        resource_id=str(user.id),
        user_id=str(user.id),
        details={"username": str(user.username), "role": role_val},
        ip_address=request.client.host if request.client else None,
    )
    return user


@router.post("/login", response_model=Token)
async def login(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Authenticates user credentials and issues a signed JWT token."""
    stmt = select(User).where(User.username == login_data.username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    role_val = getattr(user.role, "value", str(user.role))
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.username), "role": role_val, "user_id": str(user.id)},
        expires_delta=access_token_expires,
    )

    await audit_service.log_event(
        db=db,
        action="USER_LOGIN_SUCCESS",
        resource_type="USER",
        resource_id=str(user.id),
        user_id=str(user.id),
        details={"username": str(user.username)},
        ip_address=request.client.host if request.client else None,
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=str(user.id),
        username=str(user.username),
        role=user.role,
    )


@router.get("/me", response_model=UserResponse)
async def get_my_profile(current_user: Any = Depends(get_current_user)) -> Any:
    """Retrieves the authenticated user profile."""
    return current_user

