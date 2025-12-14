from typing import List
import asyncio
import aiohttp

from .base import BaseAnalyzer
from .dto import AnalyzerResult, VulnerabilityDTO, PayloadResult
from ..scanner.dto import Form
from models.vulnerability import VulnerabilityTypesEnum, SeverityEnum
from utils.logging import app_logger


class BruteforceAnalyzer(BaseAnalyzer):
    """Bruteforce Protection Analyzer"""
    
    def __init__(self, site_map, timeout: int = 10, delay: float = 0.1):
        super().__init__(site_map, timeout, delay)
        self.attempts_count = 8  # Количество попыток для теста
    
    def get_payloads(self) -> List[str]:
        """Не используется для Bruteforce"""
        return []
    
    def check_vulnerability(self, payload_result: PayloadResult) -> bool:
        """Не используется для Bruteforce"""
        return False
    
    def create_vulnerability(
        self,
        url: str,
        param: str,
        method: str,
        successful_payload: PayloadResult
    ) -> VulnerabilityDTO:
        """Создает VulnerabilityDTO для Bruteforce"""
        return VulnerabilityDTO(
            name=f"Missing Bruteforce Protection on {url}",
            description=(
                f"**Form:** {method} {url}\n"
                f"**Parameter:** {param}\n\n"
                f"**Issue:** This authentication form does not implement protection "
                f"against bruteforce attacks. An attacker can try unlimited password combinations.\n\n"
                f"**Test Results:**\n"
                f"- Sent {self.attempts_count} failed login attempts\n"
                f"- No rate limiting detected\n"
                f"- No CAPTCHA protection found\n"
                f"- No account lockout mechanism\n\n"
                f"**Attack scenario:**\n"
                f"1. Attacker identifies login form\n"
                f"2. Uses automated tools (Hydra, Medusa) to try common passwords\n"
                f"3. Successfully gains access after N attempts\n\n"
                f"**Impact:**\n"
                f"- Unauthorized access to user accounts\n"
                f"- Account compromise\n"
                f"- Credential stuffing attacks\n"
                f"- Data breach\n\n"
                f"**Recommendation:**\n"
                f"- Implement rate limiting (max 5 attempts per 15 minutes)\n"
                f"- Add CAPTCHA after 3 failed attempts\n"
                f"- Implement account lockout after N failed attempts\n"
                f"- Add exponential backoff delays\n"
                f"- Monitor and alert on suspicious login patterns\n"
                f"- Use Multi-Factor Authentication (MFA)\n"
                f"- Log all failed login attempts"
            ),
            vuln_type=VulnerabilityTypesEnum.BRUTE,
            severity=SeverityEnum.HIGH,
            url_path=url,
            parameter=param,
            method=method,
            evidence=successful_payload.evidence or "No bruteforce protection",
            cwe_id='CWE-307'
        )
    
    def _is_login_form(self, form: Form) -> bool:
        """
        Определяет является ли форма формой логина
        По наличию полей: password + (username/email/login)
        """
        has_password = False
        has_identifier = False
        
        for field in form.fields:
            field_name_lower = field.name.lower()
            field_type = field.field_type
            
            # Проверяем наличие поля пароля
            if field_type == 2 or 'password' in field_name_lower or 'pass' in field_name_lower:
                has_password = True
            
            # Проверяем наличие поля логина
            if any(keyword in field_name_lower for keyword in ['username', 'email', 'login', 'user']):
                has_identifier = True
        
        return has_password and has_identifier
    
    def _has_captcha(self, form: Form) -> bool:
        """Проверяет наличие капчи"""
        captcha_patterns = [
            'captcha',
            'recaptcha',
            'g-recaptcha',
            'h-captcha',
            'hcaptcha',
        ]
        
        for field in form.fields:
            field_name_lower = field.name.lower()
            for pattern in captcha_patterns:
                if pattern in field_name_lower:
                    return True
        
        return False
    
    async def _test_rate_limiting(self, form: Form, endpoint_url: str) -> dict:
        """
        Тестирует rate limiting отправляя множественные запросы
        """
        base_data = form.to_dict()
        
        # Подготавливаем тестовые данные
        test_credentials = []
        for i in range(self.attempts_count):
            data = base_data.copy()
            # Заполняем поля неправильными данными
            for field in form.fields:
                field_name_lower = field.name.lower()
                if 'password' in field_name_lower or 'pass' in field_name_lower:
                    data[field.name] = f'wrong_password_{i}'
                elif any(k in field_name_lower for k in ['username', 'email', 'login', 'user']):
                    data[field.name] = 'test_user'
            
            test_credentials.append(data)
        
        # Отправляем запросы
        results = []
        blocked = False
        
        app_logger.info(
            f"[{self.analyzer_name}] Testing rate limiting with {self.attempts_count} attempts"
        )
        
        for i, creds in enumerate(test_credentials):
            result = await self._send_request(
                url=form.action.url,
                method=form.method.name,
                data=creds
            )
            
            if result:
                results.append(result)
                
                # Проверяем блокировку
                if result.response_code == 429:  # Too Many Requests
                    blocked = True
                    app_logger.info(
                        f"[{self.analyzer_name}] Rate limiting detected: HTTP 429 after {i+1} attempts"
                    )
                    break
                
                # Проверяем текстовые индикаторы блокировки
                if self._check_lockout_indicators(result.response_body):
                    blocked = True
                    app_logger.info(
                        f"[{self.analyzer_name}] Account lockout detected after {i+1} attempts"
                    )
                    break
            
            # Небольшая задержка между попытками
            await asyncio.sleep(self.delay)
        
        return {
            'blocked': blocked,
            'attempts': len(results),
            'results': results
        }
    
    def _check_lockout_indicators(self, response_body: str) -> bool:
        """Проверяет индикаторы блокировки в response"""
        lockout_patterns = [
            'too many attempts',
            'account locked',
            'account disabled',
            'temporarily blocked',
            'try again later',
            'rate limit exceeded',
            'suspicious activity',
        ]
        
        response_lower = response_body.lower()
        for pattern in lockout_patterns:
            if pattern in response_lower:
                return True
        
        return False
    
    async def analyze(self) -> AnalyzerResult:
        """Главный метод анализа"""
        import time
        start_time = time.time()
        
        async with aiohttp.ClientSession() as session:
            self._session = session
            
            app_logger.info(f"[{self.analyzer_name}] Starting bruteforce protection analysis")
            
            for endpoint_url, endpoint in self.site_map.endpoints.items():
                self.result.tested_endpoints += 1
                
                # Тестируем формы логина
                for form in endpoint.forms:
                    # Пропускаем не-логин формы
                    if not self._is_login_form(form):
                        continue
                    
                    app_logger.info(
                        f"[{self.analyzer_name}] Found login form: "
                        f"{form.method.name} {form.action.url}"
                    )
                    
                    # Проверяем наличие капчи
                    if self._has_captcha(form):
                        app_logger.info(
                            f"[{self.analyzer_name}] CAPTCHA detected - form is protected"
                        )
                        continue
                    
                    # Тестируем rate limiting
                    test_result = await self._test_rate_limiting(form, endpoint_url)
                    
                    if not test_result['blocked']:
                        # Нет защиты - создаём уязвимость
                        vuln = self.create_vulnerability(
                            url=form.action.url,
                            param=form.form_id or 'login_form',
                            method=form.method.name,
                            successful_payload=PayloadResult(
                                payload="",
                                response_code=0,
                                response_time=0,
                                response_body="",
                                is_vulnerable=True,
                                evidence=f"Sent {test_result['attempts']} attempts without blocking"
                            )
                        )
                        self.result.vulnerabilities.append(vuln)
                        
                        app_logger.warning(
                            f"[{self.analyzer_name}] BRUTEFORCE VULNERABILITY: "
                            f"{form.action.url} has no bruteforce protection"
                        )
                    else:
                        app_logger.info(
                            f"[{self.analyzer_name}] Bruteforce protection detected on {form.action.url}"
                        )
            
            self.result.duration = time.time() - start_time
            
            app_logger.info(
                f"[{self.analyzer_name}] Analysis complete: "
                f"{len(self.result.vulnerabilities)} vulnerabilities found"
            )
        
        return self.result
