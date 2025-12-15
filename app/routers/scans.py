from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from typing import List
from fastapi import UploadFile, File
from fastapi.responses import HTMLResponse, FileResponse, Response
import os
import uuid
import tempfile
from datetime import datetime

from database import get_db 
from schemas import ScanCreate, ScanResponse, ScanListItem
from dependencies import require_analyst_or_higher, require_dev_or_higher
from models.user import User
from models.scan import Scan, ScanStatusEnum
from models.vulnerability import Vulnerability
from services.fake_scanner import run_fake_scan
from services import ScannerService, SASTService
from utils.logging import app_logger
from utils.markdown_helper import markdown_to_safe_html
from core.reports import HTMLReportGenerator, PDFReportGenerator
from config import cur_lang


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
    background_tasks.add_task(run_fake_scan if scan_data.debug else ScannerService.run_scan, new_scan.id)
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
            selectinload(Scan.vulnerabilities).selectinload(Vulnerability.cwe),
        )
        .where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        app_logger.warning(f"[API] Scan #{scan_id} not found")
        raise HTTPException(status_code=404, detail=f"Scan with id {scan_id} not found")
    
    for vuln in scan.vulnerabilities:
        vuln: Vulnerability
        if not vuln.description:
            continue
        vuln.description = markdown_to_safe_html(vuln.description)
    
    app_logger.info(
        f"[API] Retrieved scan #{scan_id} details "
        f"(status: {scan.status_enum.syslabel}, vulnerabilities: {len(scan.vulnerabilities)})"
    )
    
    return scan


@router.post("/sast", response_model=ScanResponse, status_code=201)
async def create_sast_scan(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_higher)
):
    """
    Создаёт SAST скан из загруженного архива с кодом.
    
    - **file**: ZIP или TAR.GZ архив с исходным кодом
    """
    # Проверяем формат файла
    if not (file.filename.endswith('.zip') or file.filename.endswith('.tar.gz') or file.filename.endswith('.tar')):
        raise HTTPException(
            status_code=400, 
            detail="Only .zip, .tar.gz, .tar archives are supported"
        )
    
    # Создаём папку uploads если нет
    os.makedirs("uploads", exist_ok=True)
    
    # Сохраняем файл с уникальным именем
    file_id = str(uuid.uuid4())
    file_ext = '.zip' if file.filename.endswith('.zip') else '.tar.gz'
    file_path = f"uploads/sast_{file_id}{file_ext}"
    
    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)
    
    app_logger.info(f"[API] Uploaded SAST archive: {file.filename} -> {file_path} ({len(content)} bytes)")
    
    # Создаём Scan в БД
    new_scan = Scan(
        target_url=f"http://sast.local/{file.filename}",
        status=ScanStatusEnum.PENDING,
        user_id=current_user.id
    )
    
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan, ["user", "vulnerabilities"])
    
    app_logger.info(
        f"[API] User #{current_user.id} created SAST scan #{new_scan.id} "
        f"for file: {file.filename}"
    )
    
    # Запускаем SAST в фоне
    background_tasks.add_task(SASTService.run_sast_scan, new_scan.id, file_path)
    
    return new_scan


@router.get("/{scan_id}/report/html", response_class=HTMLResponse)
async def get_scan_report_html(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_dev_or_higher)
):
    """Генерирует HTML отчёт для скана"""
    # Получаем скан с уязвимостями
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    for vuln in scan.vulnerabilities:
        vuln: Vulnerability
        if not vuln.description:
            continue
        vuln.description = markdown_to_safe_html(vuln.description)
    # Генерируем отчёт
    generator = HTMLReportGenerator(cur_lang.get())
    html = generator.generate(scan, scan.vulnerabilities)
    
    return HTMLResponse(content=html)


@router.get("/{scan_id}/report/html/download")
async def download_scan_report_html(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_dev_or_higher)
):
    """Скачать HTML отчёт как файл"""
    # Получаем скан
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities).selectinload(Vulnerability.cwe))
        .where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    for vuln in scan.vulnerabilities:
        vuln: Vulnerability
        if not vuln.description:
            continue
        vuln.description = markdown_to_safe_html(vuln.description)
    # Генерируем HTML
    generator = HTMLReportGenerator(cur_lang.get())
    html = generator.generate(scan, scan.vulnerabilities)
    
    # Сохраняем во временный файл
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.html', encoding='utf-8')
    temp_file.write(html)
    temp_file.close()
    
    # Формируем имя файла
    filename = f"scan_report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    # Отдаём файл
    return FileResponse(
        path=temp_file.name,
        filename=filename,
        media_type='text/html',
        background=lambda: os.unlink(temp_file.name)  # Удаляем после отдачи
    )


@router.get("/{scan_id}/report/pdf")
async def get_scan_report_pdf(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_dev_or_higher)
):
    """Генерирует и скачивает PDF отчёт для скана"""
    # Получаем скан с уязвимостями
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    for vuln in scan.vulnerabilities:
        vuln: Vulnerability
        if not vuln.description:
            continue
        vuln.description = markdown_to_safe_html(vuln.description)
    # Генерируем PDF
    generator = PDFReportGenerator(cur_lang.get())
    pdf_bytes = generator.generate(scan, scan.vulnerabilities)
    
    # Формируем имя файла
    filename = f"scan_report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    return Response(
        content=pdf_bytes,
        media_type='application/pdf',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"'
        }
    )
