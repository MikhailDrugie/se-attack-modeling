from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from database import get_db
from models.cwe import CWE
from schemas import CWEResponse
from dependencies import get_current_user

router = APIRouter(prefix="/cwe", tags=["CWE"])


@router.get("/", response_model=List[CWEResponse])
async def get_all_cwe(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Получить список всех CWE"""
    result = await db.execute(select(CWE).order_by(CWE.id))
    cwes = result.scalars().all()
    return cwes


@router.get("/{cwe_id}", response_model=CWEResponse)
async def get_cwe_by_id(
    cwe_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Получить конкретный CWE по ID"""
    result = await db.execute(select(CWE).where(CWE.id == cwe_id))
    cwe = result.scalar_one_or_none()
    
    if not cwe:
        raise HTTPException(status_code=404, detail="CWE not found")
    
    return cwe
