import asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import async_session
from core.engine.core import ScanEngine
from models.scan import Scan, ScanStatusEnum
from utils.logging import app_logger


class ScannerService:
    """
    Сервис для запуска сканирований
    Использует реальный ScanEngine вместо фейковых данных
    """
    
    @staticmethod
    async def run_scan(scan_id: int):
        """
        Запускает реальное сканирование для указанного scan_id
        
        Args:
            scan_id: ID скана из БД
        """
        async with async_session() as db:
            db: AsyncSession
            
            # Получаем Scan из БД
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            
            if not scan:
                app_logger.error(f"[SCAN #{scan_id}] Scan not found in database!")
                return
            
            app_logger.info(
                f"[SCAN #{scan_id}] Starting REAL scan for {scan.target_url}"
            )
            
            try:
                # Создаем и запускаем реальный Engine
                engine = ScanEngine(
                    db_session=db,
                    scan_id=scan_id,
                    target_url=scan.target_url,
                    max_depth=3,
                    max_concurrent=10
                )
                
                await engine.run()
                
                # Получаем и логируем сводку
                summary = engine.get_summary()
                app_logger.info(
                    f"[SCAN #{scan_id}] Scan completed successfully. "
                    f"Summary: {summary}"
                )
                
            except Exception as e:
                app_logger.error(f"[SCAN #{scan_id}] Scan failed: {str(e)}")
                
                # Обновляем статус на FAILED если еще не обновлен
                result = await db.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()
                if scan and scan.status != ScanStatusEnum.FAILED:
                    scan.status = ScanStatusEnum.FAILED
                    await db.commit()
