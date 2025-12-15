from typing import List
import re

from .base import BaseAnalyzer
from .dto import AnalyzerResult, VulnerabilityDTO, PayloadResult
from models.vulnerability import VulnerabilityTypesEnum, SeverityEnum
from utils.logging import app_logger


class CSRFAnalyzer(BaseAnalyzer):
    """CSRF (Cross-Site Request Forgery) Analyzer"""
    
    def get_payloads(self) -> List[str]:
        """
        Для CSRF мы не отправляем payload,
        а проверяем наличие защиты
        """
        return []
    
    def check_vulnerability(self, payload_result: PayloadResult) -> bool:
        """Не используется для CSRF"""
        return False
    
    def create_vulnerability(
        self,
        url: str,
        param: str,
        method: str,
        successful_payload: PayloadResult
    ) -> VulnerabilityDTO:
        """Создает VulnerabilityDTO для CSRF"""
        return VulnerabilityDTO(
            name=f"CSRF vulnerability in form {method} {url}",
            description=(
                f"**Form:** {method} {url}\n\n"
                f"**Issue:** This form does not implement CSRF protection. "
                f"An attacker can trick a user into submitting this form without their knowledge.\n\n"
                f"**Attack scenario:**\n"
                f"1. Attacker creates a malicious website with hidden form\n"
                f"2. Victim visits attacker's website while authenticated on target site\n"
                f"3. Hidden form auto-submits to target site using victim's session\n"
                f"4. Target site processes request as legitimate\n\n"
                f"**Impact:**\n"
                f"- Unauthorized actions performed on behalf of victim\n"
                f"- Data modification/deletion\n"
                f"- Account takeover in some cases\n"
                f"- Financial fraud\n\n"
                f"**Recommendation:**\n"
                f"- Implement CSRF tokens (synchronizer token pattern)\n"
                f"- Use SameSite cookie attribute\n"
                f"- Verify Referer/Origin headers\n"
                f"- Require re-authentication for sensitive actions\n"
                f"- Use CSRF protection middleware (Django, Flask-WTF, etc.)"
            ),
            vuln_type=VulnerabilityTypesEnum.CSRF,
            severity=SeverityEnum.HIGH,
            url_path=url,
            parameter=param,
            method=method,
            evidence="No CSRF token detected",
            cwe_id='CWE-352'
        )
    
    async def analyze(self) -> AnalyzerResult:
        """
        Анализирует формы на наличие CSRF защиты
        """
        import time
        start_time = time.time()
        
        app_logger.info(f"[{self.analyzer_name}] Starting CSRF analysis")
        
        # Проходим по всем эндпоинтам
        for endpoint_url, endpoint in self.site_map.endpoints.items():
            self.result.tested_endpoints += 1
            
            # Проверяем формы
            for form in endpoint.forms:
                # Пропускаем GET формы (они не подвержены CSRF)
                if form.method.name == 'GET':
                    continue
                
                app_logger.info(
                    f"[{self.analyzer_name}] Testing form "
                    f"{form.method.name} {form.action.url}"
                )
                
                # Проверяем наличие CSRF токена
                has_csrf_token = self._check_csrf_token(form)
                
                if not has_csrf_token:
                    vuln = self.create_vulnerability(
                        url=form.action.url,
                        param=form.form_id or 'unknown',
                        method=form.method.name,
                        successful_payload=PayloadResult(
                            payload="",
                            response_code=0,
                            response_time=0,
                            response_body="",
                            is_vulnerable=True,
                            evidence="No CSRF token detected"
                        )
                    )
                    self.result.vulnerabilities.append(vuln)
                    
                    app_logger.warning(
                        f"[{self.analyzer_name}] CSRF VULNERABILITY: "
                        f"{form.method.name} {form.action.url} has no CSRF protection"
                    )
        
        self.result.duration = time.time() - start_time
        
        app_logger.info(
            f"[{self.analyzer_name}] Analysis complete: "
            f"{len(self.result.vulnerabilities)} vulnerabilities found"
        )
        
        return self.result
    
    def _check_csrf_token(self, form) -> bool:
        """
        Проверяет наличие CSRF токена в форме
        
        Признаки CSRF защиты:
        1. Hidden поле с названием типа csrf_token, _token, csrfmiddlewaretoken
        2. Meta тег с csrf токеном
        3. Header X-CSRF-Token (проверяется косвенно)
        """
        csrf_field_patterns = [
            r'csrf',
            r'_token',
            r'authenticity_token',
            r'xsrf',
            r'anti-forgery',
        ]
        
        # Проверяем поля формы
        for field in form.fields:
            # Ищем hidden поля с csrf в названии
            if field.field_type == 6:  # HIDDEN
                field_name_lower = field.name.lower()
                for pattern in csrf_field_patterns:
                    if re.search(pattern, field_name_lower):
                        app_logger.info(
                            f"[{self.analyzer_name}] CSRF token found: {field.name}"
                        )
                        return True
        
        # Если не нашли - уязвимость
        return False
