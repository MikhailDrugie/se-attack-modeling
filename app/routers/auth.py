from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from database import get_db
from models.user import User, UserStatusEnum
from utils.security import verify_password, create_access_token
from schemas import UserResponse
from utils.logging import app_logger


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


class LoginRequest(BaseModel):
    """Модель запроса для логина"""
    username: str
    password: str


class TokenResponse(BaseModel):
    """Модель ответа с JWT токеном"""
    access_token: str
    user: UserResponse


@router.post("/login", response_model=TokenResponse)
async def login(
    credentials: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Авторизация пользователя.
    
    Возвращает JWT токен для дальнейшего использования в защищенных эндпоинтах.
    
    - **username**: Имя пользователя
    - **password**: Пароль в открытом виде
    
    Возвращает:
    - **access_token**: JWT токен
    - **user**: Информация о пользователе
    """
    result = await db.execute(
        select(User).where(User.username == credentials.username)
    )
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(credentials.password, user.password_hash):
        app_logger.warning(
            f"[AUTH] Failed login attempt for username: {credentials.username}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if user.status != UserStatusEnum.ACTIVE:
        app_logger.warning(
            f"[AUTH] Login attempt for non-active user: {credentials.username} "
            f"(status: {user.status_enum.syslabel})"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User account is {user.status_enum.syslabel.lower()}"
        )    
    access_token = create_access_token(data={"sub": str(user.id)})    
    app_logger.info(
        f"[AUTH] User {user.username} logged in successfully "
        f"(ID: {user.id}, Role: {user.role_enum.syslabel})"
    )    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )
