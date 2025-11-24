from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from typing import List

from database import get_db 
from schemas import ScanCreate, ScanResponse, ScanListItem
from dependencies import require_analyst_or_higher, require_dev_or_higher
from models.user import User
from models.scan import Scan, ScanStatusEnum
from services.scanner import run_fake_scan
from utils.logging import app_logger


router = APIRouter(
    prefix="/scans",
    tags=["Scans"]
)


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_higher)
):
    """
    Создает новый скан и запускает его в фоновом режиме. TODO: Фейковое сканирование на данный момент
    
    - **target_url**: URL для сканирования
    """
    new_scan = Scan(
        target_url=str(scan_data.target_url),
        status=ScanStatusEnum.PENDING,
        user_id=current_user.id
    )
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan, ["user", "vulnerabilities"])
    app_logger.info(
        f"[API] User #{new_scan.user_id} created scan #{new_scan.id} "
        f"for target: {new_scan.target_url}"
    )
    background_tasks.add_task(run_fake_scan, new_scan.id)
    return new_scan


@router.get("/", response_model=List[ScanListItem])
async def list_scans(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_dev_or_higher)
):
    """
    Возвращает список всех сканов.
    
    - **limit**: Максимальное количество записей (по умолчанию 50)
    - **offset**: Смещение для пагинации
    """
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.user), selectinload(Scan.vulnerabilities))
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    scans = result.scalars().all()
    app_logger.info(f"[API] Listed {len(scans)} scans (limit={limit}, offset={offset})")
    return scans


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_details(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_dev_or_higher)
):
    """
    Возвращает детальную информацию о скане, включая найденные уязвимости.
    
    - **scan_id**: ID скана
    """
    result = await db.execute(
        select(Scan)
        .options(
            selectinload(Scan.user),
            selectinload(Scan.vulnerabilities)
        )
        .where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        app_logger.warning(f"[API] Scan #{scan_id} not found")
        raise HTTPException(status_code=404, detail=f"Scan with id {scan_id} not found")
    app_logger.info(
        f"[API] Retrieved scan #{scan_id} details "
        f"(status: {scan.status_enum.syslabel}, vulnerabilities: {len(scan.vulnerabilities)})"
    )
    
    return scan
