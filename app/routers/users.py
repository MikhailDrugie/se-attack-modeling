from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from database import get_db
from schemas import UserCreate, UserResponse
from models.user import User, UserStatusEnum, UserRoleEnum
from utils.security import hash_password
from utils.logging import app_logger
from dependencies import get_current_user, get_current_admin


router = APIRouter(
    prefix="/users",
    tags=["Users"]
)


@router.post("/", response_model=UserResponse, status_code=201)
async def create_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_admin: User = Depends(get_current_admin)
):
    """Создание нового пользователя (только админ)"""
    result = await db.execute(
        select(User).where(User.username == user_data.username)
    )
    existing_user = result.scalar_one_or_none()
    
    if existing_user:
        app_logger.warning(
            f"[API] Admin {current_admin.username} tried to create existing user: {user_data.username}"
        )
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Создаем юзера
    new_user = User(
        username=user_data.username,
        password_hash=hash_password(user_data.password),
        role=user_data.role,
        status=UserStatusEnum.ACTIVE
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    app_logger.info(
        f"[API] Admin {current_admin.username} created user: {new_user.username} "
        f"(ID: {new_user.id}, Role: {new_user.role_enum.syslabel})"
    )
    
    return new_user


@router.get("/", response_model=List[UserResponse])
async def list_users(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Список пользователей (только админ)"""
    result = await db.execute(
        select(User)
        .where(User.status != UserStatusEnum.SOFT_DELETE)
        .order_by(User.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    users = result.scalars().all()
    
    app_logger.info(f"[API] User {current_user.username} listed {len(users)} users")
    
    return users


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """Информация о текущем пользователе"""
    return current_user


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Информация о данном пользователе"""
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user or user.status == UserStatusEnum.SOFT_DELETE:
        raise HTTPException(status_code=404, detail=f"User with id {user_id} not found")
    
    app_logger.info(f"[API] User {current_user.username} retrieved user #{user_id}")
    
    return user


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_admin: User = Depends(get_current_admin)  # Только админы
):
    """Удаление (soft delete)"""
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail=f"User with id {user_id} not found")
    
    # Нельзя удалить себя
    if user.id == current_admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    # Soft delete
    user.status = UserStatusEnum.SOFT_DELETE
    await db.commit()
    
    app_logger.info(
        f"[API] Admin {current_admin.username} deleted user #{user_id} ({user.username})"
    )
    
    return None
