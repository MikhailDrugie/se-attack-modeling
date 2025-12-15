from typing import List
import re
from models.vulnerability import VulnerabilityTypesEnum, SeverityEnum
from .base import BaseAnalyzer
from .dto import VulnerabilityDTO, PayloadResult

class XSSAnalyzer(BaseAnalyzer):
    """XSS (Cross-Site Scripting) Analyzer"""
    
    def get_payloads(self) -> List[str]:
        """XSS payloads для тестирования"""
        return [
            # Базовые векторы
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            
            # Обход фильтров
            "<ScRiPt>alert('XSS')</sCrIpT>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
            "<iframe src=javascript:alert('XSS')>",
            
            # Event handlers
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            
            # URL-based
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            
            # Obfuscation
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            
            # HTML5 vectors
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            
            # Bypass attempts
            "<scr<script>ipt>alert('XSS')</script>",
            "<<SCRIPT>alert('XSS');//<</SCRIPT>",
        ]
    
    def check_vulnerability(self, payload_result: PayloadResult) -> bool:
        """
        Проверяет наличие XSS уязвимости в response
        
        Ищет:
        1. Payload в чистом виде в HTML
        2. Payload внутри атрибутов тегов
        3. Payload в JS контексте
        """
        response = payload_result.response_body.lower()
        payload = payload_result.payload.lower()
        
        # Проверяем что payload отразился в ответе
        if payload not in response:
            return False
        
        # Поиск опасных паттернов
        dangerous_patterns = [
            r'<script[^>]*>.*?' + re.escape(payload),  # В <script> теге
            r'<.*?on\w+\s*=.*?' + re.escape(payload),  # В event handler
            r'<iframe[^>]*src\s*=.*?' + re.escape(payload),  # В iframe src
            r'<img[^>]*src\s*=.*?' + re.escape(payload),  # В img src
            r'<svg[^>]*onload\s*=.*?' + re.escape(payload),  # В SVG onload
            r'javascript:.*?' + re.escape(payload),  # В javascript: URL
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                # Сохраняем evidence
                match = re.search(pattern, response, re.IGNORECASE)
                payload_result.evidence = match.group(0)[:200] if match else payload
                return True
        
        # Проверяем базовый случай - payload в HTML без кодирования
        if '<' in payload and '>' in payload:
            # Ищем payload без HTML-кодирования
            if payload in response and '&lt;' not in response.replace(payload, ''):
                payload_result.evidence = payload
                return True
        
        return False
    
    def create_vulnerability(
        self, 
        url: str, 
        param: str, 
        method: str,
        successful_payload: PayloadResult
    ) -> VulnerabilityDTO:
        """Создает VulnerabilityDTO для XSS"""
        
        # Определяем severity по типу XSS
        severity = SeverityEnum.HIGH
        if 'script' in successful_payload.payload.lower():
            severity = SeverityEnum.CRITICAL  # <script> теги - критично
        
        name = f"XSS vulnerability in '{param}' parameter"
        
        description = (
            f"Cross-Site Scripting (XSS) vulnerability detected in {method} parameter '{param}'. "
            f"The application reflects user input without proper sanitization, allowing execution "
            f"of arbitrary JavaScript code in victim's browser.\n\n"
            f"**Payload used:** `{successful_payload.payload}`\n"
            f"**Evidence:** `{successful_payload.evidence[:200]}`\n\n"
            f"**Attack scenario:**\n"
            f"1. Attacker crafts malicious URL/form with XSS payload\n"
            f"2. Victim visits the URL or submits the form\n"
            f"3. Malicious script executes in victim's context\n"
            f"4. Attacker can steal cookies, session tokens, or perform actions on behalf of victim\n\n"
            f"**Recommendation:**\n"
            f"- Implement proper output encoding/escaping\n"
            f"- Use Content Security Policy (CSP) headers\n"
            f"- Validate and sanitize all user inputs\n"
            f"- Use HTTPOnly and Secure flags for sensitive cookies"
        )
        
        return VulnerabilityDTO(
            name=name,
            description=description,
            vuln_type=VulnerabilityTypesEnum.XSS,
            severity=severity,
            url_path=url,
            parameter=param,
            method=method,
            payload=successful_payload.payload,
            evidence=successful_payload.evidence or successful_payload.payload[:200],
            all_payloads=[successful_payload],
            cwe_id="CWE-79"
        )
