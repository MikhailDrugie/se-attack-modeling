from abc import ABC, abstractmethod
from typing import List, Dict
import aiohttp
import asyncio
import time

from ..scanner.mapper import SiteMap, EndpointInfo
from ..scanner.dto import Form
from utils.logging import app_logger
from models.vulnerability import VulnerabilityTypesEnum, SeverityEnum
from .dto import AnalyzerResult, VulnerabilityDTO, PayloadResult

class BaseAnalyzer(ABC):
    """Базовый класс для анализаторов уязвимостей"""
    
    def __init__(self, site_map: SiteMap, timeout: int = 10, delay: float = 0.1):
        self.site_map = site_map
        self.timeout = timeout
        self.delay = delay
        
        self.analyzer_name = self.__class__.__name__
        self.result = AnalyzerResult(analyzer_name=self.analyzer_name)
        
        self._session: aiohttp.ClientSession | None = None
    
    @abstractmethod
    def get_payloads(self) -> List[str]:
        """Возвращает список payload для тестирования"""
        pass
    
    @abstractmethod
    def check_vulnerability(self, payload_result: PayloadResult) -> bool:
        """Проверяет response на наличие уязвимости"""
        pass
    
    @abstractmethod
    def create_vulnerability(
        self, 
        url: str, 
        param: str, 
        method: str,
        successful_payload: PayloadResult
    ) -> VulnerabilityDTO:
        """Создает VulnerabilityDTO из успешного payload"""
        pass
    
    async def test_form(self, endpoint_url: str, form: Form) -> List[VulnerabilityDTO]:
        """Тестирует форму на уязвимости"""
        vulnerabilities = []
        payloads = self.get_payloads()
        
        app_logger.info(f"[{self.analyzer_name}] Testing form {form.method.name} {form.action.url}")
        
        base_data = form.to_dict()
        
        # Тестируем каждое поле
        for field in form.fields:
            if field.field_type in [7, 6]:  # SUBMIT, HIDDEN
                continue
            
            for payload in payloads:
                test_data = base_data.copy()
                test_data[field.name] = payload
                
                payload_result = await self._send_request(
                    url=form.action.url,
                    method=form.method.name,
                    data=test_data
                )
                
                if payload_result and self.check_vulnerability(payload_result):
                    vuln = self.create_vulnerability(
                        url=form.action.url,
                        param=field.name,
                        method=form.method.name,
                        successful_payload=payload_result
                    )
                    vulnerabilities.append(vuln)
                    app_logger.warning(
                        f"[{self.analyzer_name}] VULNERABILITY: "
                        f"{vuln.name} in {field.name}"
                    )
                    break
                
                await asyncio.sleep(self.delay)
        
        return vulnerabilities
    
    async def test_url_params(self, endpoint: EndpointInfo) -> List[VulnerabilityDTO]:
        """Тестирует GET параметры"""
        vulnerabilities = []
        payloads = self.get_payloads()
        
        if not endpoint.pages:
            return vulnerabilities
        
        first_page = next(iter(endpoint.pages.values()))
        
        if not first_page.link.query_params:
            return vulnerabilities
        
        app_logger.info(f"[{self.analyzer_name}] Testing URL params on {endpoint.base_url}")
        
        for param_name, param_value in first_page.link.query_params.items():
            for payload in payloads:
                test_params = first_page.link.query_params.copy()
                test_params[param_name] = payload
                
                payload_result = await self._send_request(
                    url=endpoint.base_url,
                    method='GET',
                    params=test_params
                )
                
                if payload_result and self.check_vulnerability(payload_result):
                    vuln = self.create_vulnerability(
                        url=endpoint.base_url,
                        param=param_name,
                        method='GET',
                        successful_payload=payload_result
                    )
                    vulnerabilities.append(vuln)
                    app_logger.warning(
                        f"[{self.analyzer_name}] VULNERABILITY: "
                        f"{vuln.name} in {param_name}"
                    )
                    break
                
                await asyncio.sleep(self.delay)
        
        return vulnerabilities
    
    async def _send_request(
        self, 
        url: str, 
        method: str, 
        data: Dict = None,
        params: Dict = None
    ) -> PayloadResult | None:
        """Отправляет HTTP запрос"""
        start_time = time.time()
        
        try:
            payload_value = ""
            if method.upper() == 'GET' and params:
                payload_value = str(list(params.values())[0])
                async with self._session.get(url, params=params, timeout=self.timeout) as resp:
                    if resp.status >= 400:
                        app_logger.info(
                            f"[{self.analyzer_name}] Non-OK status {resp.status} for {url}"
                        )
                    
                    body = await resp.text()
                    response_time = time.time() - start_time
                    self.result.total_requests += 1
                    
                    return PayloadResult(
                        payload=payload_value,
                        response_code=resp.status,
                        response_time=response_time,
                        response_body=body,
                        is_vulnerable=False
                    )
            
            elif method.upper() == 'POST' and data:
                # Ищем payload в data (первое измененное значение)
                payload_value = str(list(data.values())[0])
                async with self._session.post(url, data=data, timeout=self.timeout) as resp:
                    body = await resp.text()
                    response_time = time.time() - start_time
                    self.result.total_requests += 1
                    
                    return PayloadResult(
                        payload=payload_value,
                        response_code=resp.status,
                        response_time=response_time,
                        response_body=body,
                        is_vulnerable=False
                    )
        
        except Exception as e:
            app_logger.error(f"[{self.analyzer_name}] Request error: {e}")
            return None
    
    async def analyze(self) -> AnalyzerResult:
        """Главный метод анализа"""
        start_time = time.time()
        
        async with aiohttp.ClientSession() as session:
            self._session = session
            
            for endpoint_url, endpoint in self.site_map.endpoints.items():
                self.result.tested_endpoints += 1
                
                # Тестируем формы
                for form in endpoint.forms:
                    vulns = await self.test_form(endpoint_url, form)
                    self.result.vulnerabilities.extend(vulns)
                
                # Тестируем URL параметры
                vulns = await self.test_url_params(endpoint)
                self.result.vulnerabilities.extend(vulns)
        
        self.result.duration = time.time() - start_time
        
        app_logger.info(
            f"[{self.analyzer_name}] Complete: "
            f"{len(self.result.vulnerabilities)} vulnerabilities found"
        )
        
        return self.result
