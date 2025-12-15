from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from datetime import datetime
from typing import List
from models.scan import Scan, ScanStatusEnum
from models.vulnerability import Vulnerability, VulnerabilityTypesEnum, SeverityEnum
from enums import Lang


class HTMLReportGenerator:
    """Генератор HTML отчётов"""
    
    def __init__(self, lang: Lang = Lang.RU):
        # Путь к шаблонам
        template_dir = Path(__file__).parent / "templates"
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))
        self.lang = lang
    
    def generate(self, scan: Scan, vulnerabilities: List[Vulnerability]) -> str:
        """
        Генерирует HTML отчёт
        
        Args:
            scan: Объект Scan из БД
            vulnerabilities: Список Vulnerability из БД
            
        Returns:
            str: HTML строка
        """
        suffix = 'eng' if self.lang == Lang.ENG else 'ru'
        template = self.env.get_template(f"report.{suffix}.html")
        
        # Маппинг severity → текст
        severity_map = {
            SeverityEnum.CRITICAL: "critical",
            SeverityEnum.HIGH: "high",
            SeverityEnum.MEDIUM: "medium",
            SeverityEnum.LOW: "low",
        }
        
        # Маппинг типов уязвимостей
        vuln_type_map = {
            VulnerabilityTypesEnum.XSS: "XSS",
            VulnerabilityTypesEnum.SQL_INJECT: "SQL Injection",
            VulnerabilityTypesEnum.CSRF: "CSRF",
            VulnerabilityTypesEnum.BRUTE: "Bruteforce",
            VulnerabilityTypesEnum.CONFIG: "Configuration",
            VulnerabilityTypesEnum.SAST: "SAST",
        }
        
        # Подсчёт по severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        # Статус скана
        scan_status_map = {
            ScanStatusEnum.PENDING: "Pending",
            ScanStatusEnum.RUNNING: "Running",
            ScanStatusEnum.COMPLETED: "Completed",
            ScanStatusEnum.FAILED: "Failed",
        }
        
        # Рендерим шаблон
        html = template.render(
            scan=scan,
            vulnerabilities=vulnerabilities,
            severity_counts=severity_counts,
            severity_map=severity_map,
            vuln_type_map=vuln_type_map,
            scan_status=scan_status_map.get(scan.status, "Unknown"),
            report_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
        return html
