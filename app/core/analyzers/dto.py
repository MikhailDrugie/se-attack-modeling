from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class PayloadResult:
    """Результат одного payload (промежуточные данные)"""
    payload: str                    # Что отправили
    response_code: int              # HTTP код
    response_time: float            # Время ответа
    response_body: str              # Тело ответа
    is_vulnerable: bool             # Найдена ли уязвимость
    evidence: Optional[str] = None  # Доказательство

@dataclass
class VulnerabilityDTO:
    """
    Промежуточная модель уязвимости (для анализатора)
    Потом маппится в ORM Vulnerability
    """
    name: str                       # Название уязвимости
    description: str                # Описание
    vuln_type: int                  # VulnerabilityTypesEnum значение
    severity: int                   # SeverityEnum значение
    url_path: str                   # URL где найдено
    
    # Дополнительные данные (не идут в БД, только для логов/отчетов)
    parameter: str = ""             # Параметр (GET/POST)
    method: str = ""                # GET/POST/etc
    payload: str = ""               # Успешный payload
    evidence: str = ""              # Кусок response с доказательством
    all_payloads: list[PayloadResult] = field(default_factory=list)
    
    cwe_id: str = "CWE-UNKNOWN"
    
    def to_orm_dict(self) -> dict:
        """Маппинг в ORM Vulnerability модель"""
        return {
            'name': self.name,
            'description': self.description,
            'type': self.vuln_type,
            'severity': self.severity,
            'url_path': self.url_path,
            'cwe_id': self.cwe_id
        }

@dataclass
class AnalyzerResult:
    """Результат работы анализатора"""
    analyzer_name: str                              # XSS/SQLi/etc
    vulnerabilities: List[VulnerabilityDTO] = field(default_factory=list)
    tested_endpoints: int = 0
    total_requests: int = 0
    duration: float = 0.0
    
    def get_by_severity(self, severity: int) -> List[VulnerabilityDTO]:
        return [v for v in self.vulnerabilities if v.severity == severity]
