from typing import Literal
from enum import IntEnum
import aiohttp
import asyncio
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass

from utils.logging import app_logger
from core.utils import url_parser
from .dto import Page


class ContentType(IntEnum):
    HTML = 1
    JSON = 2
    STATIC_IMAGE = 3
    STATIC_FILE = 4
    UNKNOWN = 5


@dataclass
class FetchResult:
    url: str
    status_code: int
    content_type: ContentType
    content: str | bytes | None | Literal[1]
    headers: dict
    mime_type: str | None 
    
    @property
    def is_html(self) -> bool:
        return self.content_type == ContentType.HTML
    
    @property
    def is_static(self) -> bool:
        return self.content_type in [ContentType.STATIC_IMAGE, ContentType.STATIC_FILE]
    
    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code <= 499
    
    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code <= 599
    
    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code <= 399


class Scraper:
    def __init__(self, base_url: str, max_depth: int = 3, max_concurrent: int = 10):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_concurrent = max_concurrent
        self.visited_urls: set[str] = set()
        self.__semaphore = asyncio.Semaphore(max_concurrent)
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        self.request_delay = 0.1
        self._last_request_time = 0
    
    @staticmethod
    def __determine_content_type(mime_type: str, url: str) -> ContentType | int:
        if 'text/html' in mime_type or 'application/xhtml' in mime_type:
            return ContentType.HTML
        elif 'application/json' in mime_type:
            return ContentType.JSON
        elif mime_type.startswith('image/'):
            return ContentType.STATIC_IMAGE
        elif mime_type in ['application/pdf', 'application/zip', 'text/plain', 
                           'application/javascript', 'text/css']:
            return ContentType.STATIC_FILE
        # Проверяем по расширению URL если MIME неясен
        if url.lower().endswith(('.jpg', '.png', '.gif', '.svg', '.webp')):
            return ContentType.STATIC_IMAGE
        elif url.lower().endswith(('.js', '.css', '.pdf', '.txt', '.xml')):
            return ContentType.STATIC_FILE
        return ContentType.UNKNOWN
    
    async def fetch(self, session: aiohttp.ClientSession, url: str, read_non_pages: bool = False) -> FetchResult | None:
        async with self.__semaphore:  # Ограничиваем параллелизм
            now = asyncio.get_event_loop().time()
            time_since_last = now - self._last_request_time
            if time_since_last < self.request_delay:
                await asyncio.sleep(self.request_delay - time_since_last)
            self._last_request_time = asyncio.get_event_loop().time()
            try:
                async with session.get(url, headers=self.headers, timeout=10) as response:
                    if response.status != 200:
                        app_logger.info(f'[SCRAPPER] Failed to fetch url {url} ({response.status})')
                        return FetchResult(
                            url=url,
                            status_code=response.status,
                            content_type=ContentType.UNKNOWN,
                            content=await response.text(),
                            headers=dict(response.headers),
                            mime_type=None
                        )
                    content_type_header = response.headers.get('Content-Type', '').lower()
                    mime_type = content_type_header.split(';')[0].strip()
                    content_type = self.__determine_content_type(mime_type, url)
                    if content_type == ContentType.HTML:
                        content = await response.text()
                    elif content_type == ContentType.JSON:
                        content = await response.json() if read_non_pages else 1  # something is present but unknown
                    else:
                        content = await response.read() if read_non_pages else 1  # something is present but unknown
                    return FetchResult(
                        url=url,
                        status_code=response.status,
                        content_type=content_type,
                        content=content,
                        headers=dict(response.headers),
                        mime_type=mime_type
                    )
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                app_logger.error(f"[SCRAPPER] Request error on {url}: {e}")
                return
            except Exception as e:
                app_logger.error(f"[SCRAPPER] Unexpected error on {url}: {e}")
                return None
    
    async def process_url(self, session: aiohttp.ClientSession, url: str, depth: int):
        stripped = url_parser.remove_query(url)
        
        if depth > self.max_depth or stripped in self.visited_urls:
            return
        
        self.visited_urls.add(stripped)
        result = await self.fetch(session, url)
        if not result:
            return
        
        # TODO: spider
        page: Page = ...
        # TODO: start filling data for mapper already?
        
        tasks = []
        for link in page.links:  # TODO: page dataclass (?)
            full_url = urljoin(stripped, link.url)
            if urlparse(full_url).netloc == urlparse(self.base_url).netloc:
                tasks.append(self.process_url(session, full_url, depth + 1))
        
        if tasks:
            await asyncio.gather(*tasks)
    
    async def run(self):
        async with aiohttp.ClientSession() as session:
            await self.process_url(session, self.base_url, 0)
        
        site_map = ...
        return site_map

