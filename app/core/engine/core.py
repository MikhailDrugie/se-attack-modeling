import asyncio
from typing import List, Type
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload  # ← NEW!

from ..scanner.crawler import Crawler
from ..scanner.mapper import SiteMap
from ..analyzers.base import BaseAnalyzer
from ..analyzers.xss import XSSAnalyzer
from ..analyzers.sqli import SQLiAnalyzer
from ..analyzers.dto import AnalyzerResult
from models.scan import Scan, ScanStatusEnum
from models.vulnerability import Vulnerability
from utils.logging import app_logger

class ScanEngine:
    """Асинхронный движок сканирования"""
    
    def __init__(
        self,
        db_session: AsyncSession,
        scan_id: int,
        target_url: str,
        max_depth: int = 3,
        max_concurrent: int = 10
    ):
        self.db = db_session
        self.scan_id = scan_id
        self.target_url = target_url
        self.max_depth = max_depth
        self.max_concurrent = max_concurrent
        
        self.scan: Scan | None = None
        self.site_map: SiteMap | None = None
        self.analyzer_results: List[AnalyzerResult] = []
    
    async def run(self):
        """Главный метод сканирования"""
        try:
            # Получаем Scan из БД с eager loading vulnerabilities
            result = await self.db.execute(
                select(Scan)
                .where(Scan.id == self.scan_id)
                .options(selectinload(Scan.vulnerabilities))  # ← FIX! Eager load
            )
            self.scan = result.scalar_one_or_none()
            
            if not self.scan:
                raise ValueError(f"Scan with id {self.scan_id} not found")
            
            # Меняем статус на RUNNING
            self.scan.status = ScanStatusEnum.RUNNING
            await self.db.commit()
            
            app_logger.info(
                f"[ENGINE #{self.scan_id}] Starting scan for {self.target_url}"
            )
            
            # 1. Сканируем сайт
            await self._scan_website()
            
            # 2. Анализируем уязвимости
            await self._analyze_vulnerabilities()
            
            # 3. Сохраняем результаты в БД
            await self._save_results()
            
            # Меняем статус на COMPLETED
            self.scan.status = ScanStatusEnum.COMPLETED
            self.scan.completed_at = datetime.now(timezone.utc)  # ← FIX! timezone aware
            await self.db.commit()
            
            # Refresh чтобы загрузить vulnerabilities после commit
            await self.db.refresh(self.scan, ['vulnerabilities'])
            
            app_logger.info(
                f"[ENGINE #{self.scan_id}] Scan COMPLETED. "
                f"Found {len(self.scan.vulnerabilities)} vulnerabilities"
            )
            
        except Exception as e:
            app_logger.error(f"[ENGINE #{self.scan_id}] Scan FAILED: {e}")
            
            if self.scan:
                self.scan.status = ScanStatusEnum.FAILED
                await self.db.commit()
            
            raise
    
    async def _scan_website(self):
        """Сканирует сайт через Crawler"""
        app_logger.info(f"[ENGINE #{self.scan_id}] Crawling {self.target_url}")
        
        crawler = Crawler(
            base_url=self.target_url,
            max_depth=self.max_depth,
            max_concurrent=self.max_concurrent
        )
        
        self.site_map = await crawler.run()
        
        app_logger.info(
            f"[ENGINE #{self.scan_id}] Crawling complete. "
            f"Found {len(self.site_map.endpoints)} endpoints, "
            f"{len(self.site_map.get_all_forms())} forms"
        )
    
    async def _analyze_vulnerabilities(self):
        """Запускает анализаторы уязвимостей"""
        if not self.site_map:
            raise RuntimeError("Site map is not available")
        
        app_logger.info(f"[ENGINE #{self.scan_id}] Starting vulnerability analysis")
        
        # Список анализаторов
        analyzers: List[Type[BaseAnalyzer]] = [
            XSSAnalyzer,
            SQLiAnalyzer,
        ]
        
        # Запускаем анализаторы параллельно
        tasks = []
        for analyzer_class in analyzers:
            analyzer = analyzer_class(self.site_map)
            tasks.append(analyzer.analyze())
        
        self.analyzer_results = await asyncio.gather(*tasks)
        
        total_vulns = sum(len(r.vulnerabilities) for r in self.analyzer_results)
        app_logger.info(
            f"[ENGINE #{self.scan_id}] Analysis complete. "
            f"Found {total_vulns} vulnerabilities"
        )
    
    async def _save_results(self):
        """Сохраняет результаты в БД"""
        app_logger.info(f"[ENGINE #{self.scan_id}] Saving results to database")
        
        for analyzer_result in self.analyzer_results:
            for vuln_dto in analyzer_result.vulnerabilities:
                vulnerability = Vulnerability(
                    scan_id=self.scan_id,
                    name=vuln_dto.name,
                    description=vuln_dto.description,
                    type=vuln_dto.vuln_type,
                    severity=vuln_dto.severity,
                    url_path=vuln_dto.url_path
                )
                
                self.db.add(vulnerability)
                
                app_logger.warning(
                    f"[ENGINE #{self.scan_id}] VULNERABILITY: {vuln_dto.name} "
                    f"(Severity: {vuln_dto.severity}) at {vuln_dto.url_path}"
                )
        
        await self.db.commit()
        
        # Посчитать vulnerabilities после commit
        result = await self.db.execute(
            select(Scan)
            .where(Scan.id == self.scan_id)
            .options(selectinload(Scan.vulnerabilities))
        )
        self.scan = result.scalar_one_or_none()
        
        app_logger.info(
            f"[ENGINE #{self.scan_id}] Saved {len(self.scan.vulnerabilities)} "
            f"vulnerabilities to database"
        )
    
    def get_summary(self) -> dict:
        """Возвращает сводку по сканированию"""
        # Защита от None
        vuln_count = len(self.scan.vulnerabilities) if self.scan and hasattr(self.scan, 'vulnerabilities') else 0
        
        return {
            'scan_id': self.scan_id,
            'target_url': self.target_url,
            'status': self.scan.status_enum.name if self.scan else 'UNKNOWN',
            'endpoints_scanned': len(self.site_map.endpoints) if self.site_map else 0,
            'forms_tested': len(self.site_map.get_all_forms()) if self.site_map else 0,
            'vulnerabilities_found': vuln_count,
            'completed_at': self.scan.completed_at.isoformat() if self.scan and self.scan.completed_at else None,
            'analyzers': [
                {
                    'name': r.analyzer_name,
                    'vulnerabilities': len(r.vulnerabilities),
                    'requests': r.total_requests,
                    'duration': f"{r.duration:.2f}s"
                }
                for r in self.analyzer_results
            ]
        }
