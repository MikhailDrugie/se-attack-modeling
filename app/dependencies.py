from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional

from database import get_db
from models.user import User, UserStatusEnum, UserRoleEnum
from utils.security import decode_access_token
from utils.logging import app_logger


# HTTP Bearer для JWT
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
    for_disabled: bool = False
) -> User:
    """Парсинг JWT, поиск пользователя по ключу `sub`"""
    token = credentials.credentials
    
    payload = decode_access_token(token)
    if not payload:
        app_logger.warning("[AUTH] Invalid JWT token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = payload.get("sub")
    if user_id is None or not str(user_id).isnumeric():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload invalid"
        )
    user_id = int(user_id)
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()    
    if not user:
        app_logger.warning(f"[AUTH] User #{user_id} from token not found in DB")
        raise HTTPException(status_code=404, detail="User not found")
    
    # Проверяем статус
    if user.status != UserStatusEnum.ACTIVE and (not for_disabled or user.status != UserStatusEnum.DISABLED):
        app_logger.warning(f"[AUTH] User #{user_id} is not active (status: {user.status_enum.syslabel})")
        raise HTTPException(status_code=403, detail="User account is disabled")
    
    app_logger.info(f"[AUTH] User authenticated: {user.username} (ID: {user.id})")
    return user


async def get_current_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Проверяет что текущий пользователь - администратор.
    
    Raises:
        HTTPException: Если у юзера нет прав админа
    """
    if current_user.role != UserRoleEnum.ADMIN:
        app_logger.warning(
            f"[AUTH] User {current_user.username} attempted admin action "
            f"(role: {current_user.role_enum.syslabel})"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    return current_user


async def verify_api_key_header(
    x_api_key: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db)
) -> User:
    """TODO: Нужна таблица api_keys или поле api_key_hash в users. текущий глобальный API ключ - `123456`"""
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required"
        )
    if x_api_key != '123456':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bad API key"
        )

    # TODO: Проверка по базе данных. Пока что хардкод для MVP    
    # raise HTTPException(status_code=501, detail="API key auth not implemented yet")


# ========== РОЛЕВЫЕ DEPENDENCIES ==========
async def require_analyst_or_higher(
    current_user: User = Depends(get_current_user)
) -> User:
    """ANALYST+"""
    if current_user.role < UserRoleEnum.ANALYST:
        app_logger.warning(
            f"[AUTH] User {current_user.username} (role: {current_user.role_enum.syslabel}) "
            f"attempted analyst-only action"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"This action requires ANALYST role or higher. Role of requester: {current_user.role_enum.syslabel}"
        )
    return current_user


async def require_dev_or_higher(
    current_user: User = Depends(get_current_user)
) -> User:
    """DEV+"""
    if current_user.role < UserRoleEnum.DEV:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    return current_user

