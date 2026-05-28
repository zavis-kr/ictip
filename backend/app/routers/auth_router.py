"""Authentication endpoints: login, register, me."""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models import User, AuditLog
from app.schemas import UserCreate, UserOut, Token, LoginRequest
from app.auth import verify_password, hash_password, create_access_token, get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=Token)
async def login(body: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="비활성화된 계정입니다")

    token = create_access_token({"sub": user.username, "role": user.role})
    user.last_login = datetime.utcnow()

    log = AuditLog(
        user_id=user.id,
        username=user.username,
        action="LOGIN",
        resource_type="auth",
        detail="로그인 성공",
        ip_address=request.client.host if request.client else None,
    )
    db.add(log)
    await db.commit()

    return Token(
        access_token=token,
        token_type="bearer",
        role=user.role,
        username=user.username,
    )


@router.post("/register", response_model=UserOut, status_code=201)
async def register(body: UserCreate, db: AsyncSession = Depends(get_db)):
    dup = await db.execute(select(User).where(User.username == body.username))
    if dup.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="이미 존재하는 사용자명입니다")
    email_dup = await db.execute(select(User).where(User.email == body.email))
    if email_dup.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="이미 사용 중인 이메일입니다")

    user = User(
        username=body.username,
        email=body.email,
        hashed_password=hash_password(body.password),
        role=body.role or "viewer",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)):
    return current_user
