import os
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from database import async_session
from core.analyzers.sast import SASTAnalyzer
from models.scan import Scan, ScanStatusEnum
from models.vulnerability import Vulnerability
from utils.logging import app_logger
from datetime import datetime, timezone


class SASTService:
    """Сервис для запуска SAST анализа"""
    
    @staticmethod
    async def run_sast_scan(scan_id: int, archive_path: str):
        """
        Запускает SAST анализ для архива
        
        Args:
            scan_id: ID скана из БД
            archive_path: Путь к архиву с кодом
        """
        async with async_session() as db:
            db: AsyncSession

            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            
            if not scan:
                app_logger.error(f"[SAST #{scan_id}] Scan not found in database!")
                return
            
            app_logger.info(f"[SAST #{scan_id}] Starting SAST analysis for {archive_path}")
            
            try:
                # Обновляем статус
                scan.status = ScanStatusEnum.RUNNING
                await db.commit()
                
                # Запускаем SAST анализ (синхронный!)
                analyzer = SASTAnalyzer(archive_path)
                sast_result = analyzer.analyze()
                
                # Сохраняем уязвимости в БД
                for vuln_dto in sast_result.vulnerabilities:
                    vulnerability = Vulnerability(
                        scan_id=scan_id,
                        name=vuln_dto.name,
                        description=vuln_dto.description,
                        type=vuln_dto.vuln_type,
                        severity=vuln_dto.severity,
                        url_path=vuln_dto.url_path,
                        cwe_id=vuln_dto.cwe_id
                    )
                    db.add(vulnerability)
                
                await db.commit()
                
                # Обновляем статус на COMPLETED
                scan.status = ScanStatusEnum.COMPLETED
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
                
                app_logger.info(
                    f"[SAST #{scan_id}] Analysis complete. "
                    f"Found {len(sast_result.vulnerabilities)} vulnerabilities "
                    f"in {sast_result.tested_endpoints} files"
                )
                
                # Удаляем архив после анализа
                try:
                    os.remove(archive_path)
                    app_logger.info(f"[SAST #{scan_id}] Removed archive {archive_path}")
                except Exception as e:
                    app_logger.warning(f"[SAST #{scan_id}] Failed to remove archive: {e}")
                
            except Exception as e:
                app_logger.error(f"[SAST #{scan_id}] Analysis failed: {str(e)}")
                
                # Обновляем статус на FAILED
                scan.status = ScanStatusEnum.FAILED
                await db.commit()
                
                # raise
