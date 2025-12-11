import asyncio
import random
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import async_session
from models.scan import Scan, ScanStatusEnum
from models.vulnerability import Vulnerability, SeverityEnum, VulnerabilityTypesEnum
from utils.logging import app_logger


# Пул фейковых уязвимостей для генерации
FAKE_VULNERABILITIES_POOL = [
    {
        "name": "SQL Injection",
        "desc": "Parameter 'id' is vulnerable to blind SQL injection. Attacker can extract database contents.",
        "severity": SeverityEnum.CRITICAL,
        "type": VulnerabilityTypesEnum.SQL_INJECT,
        "path": "/api/users?id=1"
    },
    {
        "name": "Reflected XSS",
        "desc": "Search parameter reflects user input without sanitization. XSS payload executed successfully.",
        "severity": SeverityEnum.HIGH,
        "type": VulnerabilityTypesEnum.XSS,
        "path": "/search?q=<script>alert(1)</script>"
    },
    {
        "name": "Missing CSRF Protection",
        "desc": "Form submission does not validate CSRF token. State-changing operations are vulnerable.",
        "severity": SeverityEnum.MEDIUM,
        "type": VulnerabilityTypesEnum.CSRF,
        "path": "/account/change-password"
    },
    {
        "name": "Weak Password Policy",
        "desc": "Default credentials 'admin:admin123' accepted. No password complexity requirements.",
        "severity": SeverityEnum.HIGH,
        "type": VulnerabilityTypesEnum.BRUTE,
        "path": "/admin/login"
    },
    {
        "name": "Session Fixation",
        "desc": "Session ID does not regenerate after login. Session fixation attack possible.",
        "severity": SeverityEnum.MEDIUM,
        "type": VulnerabilityTypesEnum.SESSION,
        "path": "/auth/login"
    },
    {
        "name": "Exposed .env File",
        "desc": "Environment configuration file is publicly accessible via HTTP request.",
        "severity": SeverityEnum.CRITICAL,
        "type": VulnerabilityTypesEnum.CONFIG,
        "path": "/.env"
    },
    {
        "name": "Hardcoded API Key",
        "desc": "SAST analysis detected hardcoded API key in source code (main.js:42).",
        "severity": SeverityEnum.HIGH,
        "type": VulnerabilityTypesEnum.SAST,
        "path": "/static/js/main.js"
    },
]


async def run_fake_scan(scan_id: int):
    """
    Фейковый сканер.
    Имитирует сканирование, генерирует рандомные уязвимости.
    """
    async with async_session() as db:
        db: AsyncSession
        app_logger.info(f"[SCAN #{scan_id}] Starting scan...")
        
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        
        if not scan:
            app_logger.error(f"[SCAN #{scan_id}] Scan not found in database!")
            return
        
        try:
            scan.status = ScanStatusEnum.RUNNING
            await db.commit()
            app_logger.info(f"[SCAN #{scan_id}] Status changed to RUNNING. Target: {scan.target_url}")
            
            scan_duration = random.randint(3, 7)
            app_logger.info(f"[SCAN #{scan_id}] Scanning in progress... (est. {scan_duration}s)")
            await asyncio.sleep(scan_duration)
            
            num_vulnerabilities = random.randint(1, 4)
            found_vulns = random.sample(FAKE_VULNERABILITIES_POOL, num_vulnerabilities)
            
            for vuln_data in found_vulns:
                vulnerability = Vulnerability(
                    scan_id=scan.id,
                    name=vuln_data["name"],
                    description=vuln_data["desc"],
                    severity=vuln_data["severity"],
                    type=vuln_data["type"],
                    url_path=vuln_data["path"]
                )
                db.add(vulnerability)
                app_logger.warning(
                    f"[SCAN #{scan_id}] VULNERABILITY FOUND: {vuln_data['name']} "
                    f"({vuln_data['type'].syslabel} | {vuln_data['severity'].syslabel}) at {vuln_data['path']}"
                )
            
            scan.status = ScanStatusEnum.COMPLETED
            scan.completed_at = datetime.now()
            await db.commit()
            
            app_logger.info(
                f"[SCAN #{scan_id}] Scan COMPLETED. "
                f"Found {num_vulnerabilities} vulnerabilities in {scan_duration}s"
            )
        
        except Exception as e:
            scan.status = ScanStatusEnum.FAILED
            await db.commit()
            app_logger.error(f"[SCAN #{scan_id}] Scan FAILED: {str(e)}")
