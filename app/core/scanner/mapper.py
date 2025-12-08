from dataclasses import dataclass, field
from typing import Dict, List, Set
from collections import deque
from core.utils import url_parser
from .dto import Page, Form, ContentType, FetchResult


@dataclass
class ResourceInfo:
    """Информация о ресурсе (статика, API, etc)"""
    url: str
    content_type: ContentType
    mime_type: str
    status_code: int


@dataclass
class EndpointInfo:
    """Информация об эндпоинте (сгруппированные страницы)"""
    base_url: str  # URL без query параметров
    
    # Все варианты этого эндпоинта
    pages: Dict[str, Page] = field(default_factory=dict)  # {url_with_query: Page}
    
    # Связанные ресурсы (JS, CSS, images)
    resources: List[ResourceInfo] = field(default_factory=list)
    
    # Формы со всех вариантов страницы
    forms: List[Form] = field(default_factory=list)
    
    # Граф переходов
    incoming_links: Set[str] = field(default_factory=set)  # Откуда ведут
    outgoing_links: Set[str] = field(default_factory=set)  # Куда ведут
    
    depth: int = 0  # Глубина от base_url


@dataclass
class SiteMap:
    """Полная карта сайта"""
    base_url: str
    
    # Основные эндпоинты
    endpoints: Dict[str, EndpointInfo] = field(default_factory=dict)
    
    # Статические ресурсы (не привязанные к эндпоинтам)
    static_resources: List[ResourceInfo] = field(default_factory=list)
    
    # API endpoints (JSON)
    api_endpoints: List[ResourceInfo] = field(default_factory=list)
    
    # Ошибки (404, 500, etc)
    errors: Dict[str, FetchResult] = field(default_factory=dict)
    
    # Граф для алгоритмов (adjacency list)
    graph: Dict[str, List[str]] = field(default_factory=dict)
    
    def get_all_forms(self) -> List[tuple[str, Form]]:
        """Возвращает все формы с их URL"""
        forms = []
        for endpoint_url, endpoint in self.endpoints.items():
            for form in endpoint.forms:
                forms.append((endpoint_url, form))
        return forms
    
    def get_endpoint_by_url(self, url: str) -> EndpointInfo | None:
        """Ищет эндпоинт по полному URL"""
        stripped = url_parser.remove_query(url)
        return self.endpoints.get(stripped)
    
    def to_dict(self) -> dict:
        """Экспортирует в словарь для JSON"""
        return {
            'base_url': self.base_url,
            'endpoints_count': len(self.endpoints),
            'static_resources_count': len(self.static_resources),
            'api_endpoints_count': len(self.api_endpoints),
            'errors_count': len(self.errors),
            'total_forms': len(self.get_all_forms())
        }


class Mapper:
    """Строит карту сайта из результатов Crawler"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
    
    def build_map(self, pages: dict[str, Page], fetch_results: dict[str, FetchResult]) -> SiteMap:
        """Строит карту сайта"""        
        site_map = SiteMap(base_url=self.base_url)
        
        self._group_pages(pages, site_map)
        
        self._process_fetch_results(fetch_results, site_map)
        
        self._collect_resources(site_map)
        
        self._build_graph(site_map)
        
        self._calculate_depths(site_map)
        
        self._collect_forms(site_map)
        
        return site_map
    
    def _group_pages(self, pages: Dict[str, Page], site_map: SiteMap):
        """Группирует страницы по stripped URL"""
        for url, page in pages.items():
            stripped = url_parser.remove_query(url)
            
            if stripped not in site_map.endpoints:
                site_map.endpoints[stripped] = EndpointInfo(base_url=stripped)
            
            site_map.endpoints[stripped].pages[url] = page
    
    def _process_fetch_results(self, fetch_results: Dict[str, FetchResult], site_map: SiteMap):
        """Обрабатывает все FetchResult"""
        for url, result in fetch_results.items():
            stripped = url_parser.remove_query(url)
            
            # Ошибки
            if result.is_client_error or result.is_server_error:
                site_map.errors[url] = result
                continue
            
            # Статика
            if result.is_static:
                resource = ResourceInfo(
                    url=url,
                    content_type=result.content_type,
                    mime_type=result.mime_type or 'unknown',
                    status_code=result.status_code
                )
                site_map.static_resources.append(resource)
                continue
            
            # JSON API
            if result.content_type == ContentType.JSON:
                resource = ResourceInfo(
                    url=url,
                    content_type=result.content_type,
                    mime_type=result.mime_type or 'application/json',
                    status_code=result.status_code
                )
                site_map.api_endpoints.append(resource)
    
    def _collect_resources(self, site_map: SiteMap):
        """Собирает JS/CSS со страниц"""
        for endpoint in site_map.endpoints.values():
            for page in endpoint.pages.values():
                # Scripts
                for script_url in page.scripts:
                    resource = ResourceInfo(
                        url=script_url,
                        content_type=ContentType.JAVASCRIPT,
                        mime_type='application/javascript',
                        status_code=200  # Предполагаем что доступны
                    )
                    endpoint.resources.append(resource)
                
                # Styles
                for style_url in page.styles:
                    resource = ResourceInfo(
                        url=style_url,
                        content_type=ContentType.CSS,
                        mime_type='text/css',
                        status_code=200
                    )
                    endpoint.resources.append(resource)
    
    def _build_graph(self, site_map: SiteMap):
        """Строит граф переходов между эндпоинтами"""
        for endpoint_url, endpoint in site_map.endpoints.items():
            site_map.graph[endpoint_url] = []
            
            # Проходим по всем вариантам страницы
            for page in endpoint.pages.values():
                # Обрабатываем исходящие ссылки
                for link in page.links:
                    target_stripped = url_parser.remove_query(link.url)
                    
                    # Добавляем ребро в граф
                    if target_stripped in site_map.endpoints:
                        if target_stripped not in site_map.graph[endpoint_url]:
                            site_map.graph[endpoint_url].append(target_stripped)
                        
                        # Обновляем incoming/outgoing
                        endpoint.outgoing_links.add(target_stripped)
                        site_map.endpoints[target_stripped].incoming_links.add(endpoint_url)
    
    def _calculate_depths(self, site_map: SiteMap):
        """Вычисляет глубину каждого эндпоинта от base_url через BFS"""
        base_stripped = url_parser.remove_query(self.base_url)
        
        queue = deque([(base_stripped, 0)])
        visited = {base_stripped}
        
        while queue:
            url, depth = queue.popleft()
            
            if url in site_map.endpoints:
                site_map.endpoints[url].depth = depth
            
            # Добавляем соседей
            for neighbor in site_map.graph.get(url, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, depth + 1))
    
    def _collect_forms(self, site_map: SiteMap):
        """Собирает формы со всех страниц эндпоинта"""
        for endpoint in site_map.endpoints.values():
            forms_seen = set()
            
            for page in endpoint.pages.values():
                for form in page.forms:
                    # Дедупликация форм по action + method
                    form_key = f"{form.action.url}:{form.method}"
                    if form_key not in forms_seen:
                        endpoint.forms.append(form)
                        forms_seen.add(form_key)
