from typing import List
import aiohttp
import asyncio

from .base import BaseAnalyzer
from .dto import AnalyzerResult, VulnerabilityDTO, PayloadResult
from models.vulnerability import VulnerabilityTypesEnum, SeverityEnum
from utils.logging import app_logger


class ConfigAnalyzer(BaseAnalyzer):
    """Configuration Issues Analyzer"""
    
    def __init__(self, site_map, timeout: int = 10, delay: float = 0.1):
        super().__init__(site_map, timeout, delay)
        self.base_url = site_map.base_url
    
    def get_payloads(self) -> List[str]:
        """Не используется для Config"""
        return []
    
    def check_vulnerability(self, payload_result: PayloadResult) -> bool:
        """Не используется для Config"""
        return False
    
    def create_vulnerability(
        self,
        url: str,
        param: str,
        method: str,
        successful_payload: PayloadResult
    ) -> VulnerabilityDTO:
        """Создает VulnerabilityDTO для Config"""
        vuln_name = param  # param содержит тип уязвимости
        severity = successful_payload.response_code  # храним severity в response_code
        
        cwe_mapping = {
            "Exposed .git Directory": "CWE-200",
            "Exposed .env File": "CWE-200",
            "Debug Mode Enabled": "CWE-200",
            "Server Version Disclosure": "CWE-200",
            "Directory Listing Enabled": "CWE-548",
        }
        cwe_id = cwe_mapping.get(vuln_name, "CWE-16")

        
        descriptions = {
            "Exposed .git Directory": (
                f"**URL:** {url}\n\n"
                f"**Issue:** The `.git` directory is publicly accessible. "
                f"This exposes complete source code, credentials, and development history.\n\n"
                f"**Impact:**\n"
                f"- Full source code disclosure\n"
                f"- Exposed credentials in commit history\n"
                f"- API keys and secrets in config files\n"
                f"- Information about internal structure\n\n"
                f"**Recommendation:**\n"
                f"- Block access to `.git` directory in web server config\n"
                f"- Add `deny from all` in Apache or `location ~ /\\.git` in Nginx\n"
                f"- Never deploy .git directory to production"
            ),
            "Exposed .env File": (
                f"**URL:** {url}\n\n"
                f"**Issue:** Environment configuration file is publicly accessible. "
                f"Contains sensitive credentials and API keys.\n\n"
                f"**Impact:**\n"
                f"- Database credentials exposed\n"
                f"- API keys and secrets leaked\n"
                f"- Complete system compromise\n\n"
                f"**Recommendation:**\n"
                f"- Block access to `.env` files\n"
                f"- Store secrets in environment variables\n"
                f"- Use proper .gitignore"
            ),
            "Debug Mode Enabled": (
                f"**URL:** {url}\n\n"
                f"**Issue:** Debug mode is enabled in production. "
                f"Exposes sensitive error messages and internal paths.\n\n"
                f"**Evidence:**\n"
                f"{successful_payload.evidence[:500]}\n\n"
                f"**Impact:**\n"
                f"- Full stack traces exposed\n"
                f"- Internal file paths revealed\n"
                f"- Framework/library versions disclosed\n"
                f"- Easier exploitation of vulnerabilities\n\n"
                f"**Recommendation:**\n"
                f"- Disable debug mode in production (DEBUG=False)\n"
                f"- Configure custom error pages\n"
                f"- Log errors server-side only"
            ),
            "Server Version Disclosure": (
                f"**URL:** {url}\n\n"
                f"**Issue:** Server version information is exposed in HTTP headers.\n\n"
                f"**Evidence:**\n"
                f"{successful_payload.evidence}\n\n"
                f"**Impact:**\n"
                f"- Attackers can target known vulnerabilities\n"
                f"- Information disclosure\n\n"
                f"**Recommendation:**\n"
                f"- Remove version headers (Server, X-Powered-By)\n"
                f"- Configure web server to hide version info"
            ),
            "Directory Listing Enabled": (
                f"**URL:** {url}\n\n"
                f"**Issue:** Directory listing is enabled, exposing file structure.\n\n"
                f"**Impact:**\n"
                f"- Sensitive files discovery\n"
                f"- Information disclosure\n"
                f"- Easier reconnaissance\n\n"
                f"**Recommendation:**\n"
                f"- Disable directory listing (Options -Indexes)\n"
                f"- Add index.html to all directories"
            ),
        }
        
        return VulnerabilityDTO(
            name=vuln_name,
            description=descriptions.get(vuln_name, f"Configuration issue: {vuln_name}"),
            vuln_type=VulnerabilityTypesEnum.CONFIG,
            severity=severity,
            url_path=url,
            parameter=param,
            method=method,
            evidence=successful_payload.evidence,
            cwe_id=cwe_id
        )
    
    async def analyze(self) -> AnalyzerResult:
        """Главный метод анализа"""
        import time
        start_time = time.time()
        
        async with aiohttp.ClientSession() as session:
            self._session = session
            
            app_logger.info(f"[{self.analyzer_name}] Starting configuration analysis")
            
            # 1. Проверяем открытые директории/файлы
            await self._check_exposed_files()
            
            # 2. Проверяем debug режим на существующих страницах
            await self._check_debug_mode()
            
            # 3. Проверяем server headers
            await self._check_server_headers()
            
            # 4. Проверяем directory listing
            await self._check_directory_listing()
            
            self.result.duration = time.time() - start_time
            
            app_logger.info(
                f"[{self.analyzer_name}] Analysis complete: "
                f"{len(self.result.vulnerabilities)} vulnerabilities found"
            )
        
        return self.result
    
    async def _check_exposed_files(self):
        """Проверяет открытые файлы конфигурации"""
        sensitive_paths = [
            '.git/HEAD',
            '.git/config',
            '.env',
            '.env.local',
            '.env.production',
            'config.php',
            'config.yml',
            'database.yml',
            'wp-config.php',
            'web.config',
            'phpinfo.php',
            'info.php',
            'test.php',
            'composer.json',
            'package.json',
            '.htaccess',
            'robots.txt',  # не уязвимость, но информативно
        ]
        
        from urllib.parse import urljoin
        
        for path in sensitive_paths:
            url = urljoin(self.base_url, path)
            
            try:
                async with self._session.get(url, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        
                        # Проверяем что это не 404 страница
                        if len(content) > 0 and '404' not in content[:100].lower():
                            severity = SeverityEnum.CRITICAL if '.git' in path or '.env' in path else SeverityEnum.HIGH
                            
                            vuln_name = f"Exposed {path.split('/')[-1].upper() if '.' in path else path} File"
                            if '.git' in path:
                                vuln_name = "Exposed .git Directory"
                            elif '.env' in path:
                                vuln_name = "Exposed .env File"
                            
                            vuln = self.create_vulnerability(
                                url=url,
                                param=vuln_name,
                                method='GET',
                                successful_payload=PayloadResult(
                                    payload='',
                                    response_code=severity,  # храним severity
                                    response_time=0,
                                    response_body=content[:1000],
                                    is_vulnerable=True,
                                    evidence=f"File accessible: {path}"
                                )
                            )
                            self.result.vulnerabilities.append(vuln)
                            self.result.total_requests += 1
                            
                            app_logger.warning(
                                f"[{self.analyzer_name}] EXPOSED FILE: {url}"
                            )
                    
            except Exception as e:
                app_logger.debug(f"[{self.analyzer_name}] {url} not accessible: {e}")
            
            await asyncio.sleep(self.delay)
    
    async def _check_debug_mode(self):
        """Проверяет debug режим на существующих страницах"""
        debug_indicators = [
            'debug = true',
            'debug=true',
            'debug mode',
            'traceback',
            'stack trace',
            'django.core.exceptions',
            'flask.app',
            'laravel',
            'symfony',
            'app/config/database',
            'sqlalchemy.exc',
        ]
        
        # Проверяем первые несколько страниц
        checked = 0
        for endpoint_url, endpoint in self.site_map.endpoints.items():
            if checked >= 5:  # Ограничиваем 5 страницами
                break
            
            # Берём первую страницу эндпоинта
            if endpoint.pages:
                first_page = next(iter(endpoint.pages.values()))
                
                # Проверяем response (если был сохранён)
                # В нашем случае надо заново запросить
                try:
                    async with self._session.get(endpoint_url, timeout=self.timeout) as resp:
                        if resp.status == 500:  # Server Error
                            content = await resp.text()
                            content_lower = content.lower()
                            
                            for indicator in debug_indicators:
                                if indicator in content_lower:
                                    vuln = self.create_vulnerability(
                                        url=endpoint_url,
                                        param="Debug Mode Enabled",
                                        method='GET',
                                        successful_payload=PayloadResult(
                                            payload='',
                                            response_code=SeverityEnum.MEDIUM,
                                            response_time=0,
                                            response_body=content,
                                            is_vulnerable=True,
                                            evidence=content[:500]
                                        )
                                    )
                                    self.result.vulnerabilities.append(vuln)
                                    
                                    app_logger.warning(
                                        f"[{self.analyzer_name}] DEBUG MODE: {endpoint_url}"
                                    )
                                    break
                        
                        self.result.total_requests += 1
                        
                except Exception as e:
                    app_logger.debug(f"[{self.analyzer_name}] Error checking {endpoint_url}: {e}")
                
                checked += 1
                await asyncio.sleep(self.delay)
    
    async def _check_server_headers(self):
        """Проверяет server headers"""
        try:
            async with self._session.get(self.base_url, timeout=self.timeout) as resp:
                headers = resp.headers
                
                # Проверяем Server header
                if 'Server' in headers:
                    server_value = headers['Server']
                    # Проверяем есть ли версия
                    if any(char.isdigit() for char in server_value):
                        vuln = self.create_vulnerability(
                            url=self.base_url,
                            param="Server Version Disclosure",
                            method='GET',
                            successful_payload=PayloadResult(
                                payload='',
                                response_code=SeverityEnum.LOW,
                                response_time=0,
                                response_body='',
                                is_vulnerable=True,
                                evidence=f"Server: {server_value}"
                            )
                        )
                        self.result.vulnerabilities.append(vuln)
                        
                        app_logger.warning(
                            f"[{self.analyzer_name}] SERVER VERSION EXPOSED: {server_value}"
                        )
                
                # Проверяем X-Powered-By
                if 'X-Powered-By' in headers:
                    powered_by = headers['X-Powered-By']
                    vuln = self.create_vulnerability(
                        url=self.base_url,
                        param="Server Version Disclosure",
                        method='GET',
                        successful_payload=PayloadResult(
                            payload='',
                            response_code=SeverityEnum.LOW,
                            response_time=0,
                            response_body='',
                            is_vulnerable=True,
                            evidence=f"X-Powered-By: {powered_by}"
                        )
                    )
                    self.result.vulnerabilities.append(vuln)
                    
                    app_logger.warning(
                        f"[{self.analyzer_name}] X-POWERED-BY EXPOSED: {powered_by}"
                    )
                
                self.result.total_requests += 1
                
        except Exception as e:
            app_logger.error(f"[{self.analyzer_name}] Error checking headers: {e}")
    
    async def _check_directory_listing(self):
        """Проверяет directory listing"""
        test_dirs = [
            'uploads/',
            'files/',
            'images/',
            'assets/',
            'static/',
            'media/',
        ]
        
        from urllib.parse import urljoin
        
        for dir_path in test_dirs:
            url = urljoin(self.base_url, dir_path)
            
            try:
                async with self._session.get(url, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        
                        # Признаки directory listing
                        if ('Index of' in content or 
                            'Directory listing' in content or
                            '<title>Index of' in content):
                            
                            vuln = self.create_vulnerability(
                                url=url,
                                param="Directory Listing Enabled",
                                method='GET',
                                successful_payload=PayloadResult(
                                    payload='',
                                    response_code=SeverityEnum.MEDIUM,
                                    response_time=0,
                                    response_body=content[:500],
                                    is_vulnerable=True,
                                    evidence=f"Directory listing at: {dir_path}"
                                )
                            )
                            self.result.vulnerabilities.append(vuln)
                            
                            app_logger.warning(
                                f"[{self.analyzer_name}] DIRECTORY LISTING: {url}"
                            )
                    
                    self.result.total_requests += 1
                    
            except Exception as e:
                app_logger.debug(f"[{self.analyzer_name}] {url} not accessible: {e}")
            
            await asyncio.sleep(self.delay)
