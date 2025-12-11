from bs4 import BeautifulSoup, Tag
from urllib.parse import urljoin, urlparse
from typing import List, Dict
import json
import hashlib

from utils.logging import app_logger
from core.utils import url_parser
from .dto import *

class Spider:
    """Парсит HTML страницы и извлекает данные"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
    
    def hash_structure(self, page: Page) -> str:
        """
        Хешируем ТОЛЬКО структуру:
        - Количество и типы форм
        - Количество ссылок (но не сами URL'ы, они могут меняться!)
        - Наличие определенных элементов
        """
        structure = {
            'forms_count': len(page.forms),
            'forms_structure': [
                {
                    'method': form.method,
                    'fields_count': len(form.fields),
                    'field_types': sorted([f.field_type for f in form.fields])
                }
                for form in page.forms
            ],
            'links_count': len(page.links),
            'has_title': page.title is not None,
            'scripts_count': len(page.scripts),
            'styles_count': len(page.styles)
        }
        
        structure_str = json.dumps(structure, sort_keys=True)
        return hashlib.md5(structure_str.encode('utf-8')).hexdigest()

        
    def parse(self, html: str, current_url: str) -> Page:
        """
        Парсит HTML и возвращает структурированные данные
        
        Args:
            html: HTML контент страницы
            current_url: URL текущей страницы
        
        Returns:
            PageData с извлеченными данными
        """
        soup = BeautifulSoup(html, 'lxml')  # lxml быстрее чем html.parser
        
        parsed = url_parser.full_parse(current_url)
        link = Link(parsed.raw, parsed.url, parsed.query_params)
        
        page_data = Page(link=link)
        
        page_data.title = self._extract_title(soup)
        page_data.links = self._extract_links(soup, current_url)
        page_data.forms = self._extract_forms(soup, current_url)
        page_data.meta_tags = self._extract_meta_tags(soup)
        page_data.scripts = self._extract_scripts(soup, current_url)
        page_data.styles = self._extract_stylesheets(soup, current_url)
        
        return page_data
    
    def _extract_title(self, soup: BeautifulSoup) -> Optional[str]:
        """Извлекает title страницы"""
        title_tag = soup.find('title')
        return title_tag.get_text(strip=True) if title_tag else None
    
    def _extract_links(self, soup: BeautifulSoup, current_url: str) -> List[ExtLink]:
        links = []
        visited = {current_url}
        
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            
            if href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue
            elif urlparse(urljoin(self.base_url, href)).netloc != urlparse(self.base_url).netloc:
                continue
            
            parsed = url_parser.full_parse(urljoin(current_url, href))
            if not parsed.url or parsed.clear in visited:
                continue

            extlink = ExtLink(parsed.raw, parsed.url, parsed.query_params, href)            
            clear = extlink.raw
            if '#' in extlink.raw:
                clear, extlink.anchor = extlink.raw.split('#', 1)
            links.append(extlink)
            visited.add(clear)
            
        app_logger.info(f"[SPIDER] Found {len(links)} links on {current_url}")
        return links
    
    def _extract_forms(self, soup: BeautifulSoup, current_url: str) -> List[Form]:
        """Извлекает все формы со страницы"""
        forms = []
        
        for form_tag in soup.find_all('form'):
            # Получаем атрибуты формы
            action = form_tag.get('action', '')
            method = form_tag.get('method', 'GET').upper()
            parsed = url_parser.full_parse(current_url if not action else urljoin(current_url, action))
            link = Link(parsed.raw, parsed.url, parsed.query_params)
            
            # Извлекаем поля формы
            fields = self._extract_form_fields(form_tag)
            
            form = Form(
                action=link,
                method=FormMethods.find(method),
                fields=fields,
                form_id=form_tag.get('id'),
                form_class=form_tag.get('class')
            )
            
            forms.append(form)
            app_logger.info(f"[SPIDER] Found form: {method} {action} with {len(fields)} fields")
        
        return forms
    
    def _extract_form_fields(self, form_tag: Tag) -> List[FormField]:
        """Извлекает поля из формы"""
        fields = []
        
        # Input fields
        for input_tag in form_tag.find_all('input'):
            name = input_tag.get('name')
            if not name:  # Пропускаем поля без name
                continue
            
            field = FormField(
                name=name,
                field_type=FieldType.find(input_tag.get('type', 'text').upper()),
                value=input_tag.get('value'),
                required=input_tag.has_attr('required'),
                placeholder=input_tag.get('placeholder')
            )
            fields.append(field)
        
        # Textarea fields
        for textarea in form_tag.find_all('textarea'):
            name = textarea.get('name')
            if not name:
                continue
            
            field = FormField(
                name=name,
                field_type=FieldType.TEXTAREA,
                value=textarea.get_text(strip=True),
                required=textarea.has_attr('required'),
                placeholder=textarea.get('placeholder')
            )
            fields.append(field)
        
        # Select fields
        for select in form_tag.find_all('select'):
            name = select.get('name')
            if not name:
                continue
            
            selected_option = select.find('option', selected=True)
            value = selected_option.get('value') if selected_option else None
            
            field = FormField(
                name=name,
                field_type=FieldType.SELECT,
                value=value,
                required=select.has_attr('required'),
                data=select.find('option')
            )
            fields.append(field)
        
        return fields
    
    def _extract_meta_tags(self, soup: BeautifulSoup) -> Dict[str, str]:
        """Извлекает meta теги"""
        meta_tags = {}
        
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property')
            content = meta.get('content')
            
            if name and content:
                meta_tags[name] = content
        
        return meta_tags
    
    def _extract_scripts(self, soup: BeautifulSoup, current_url: str) -> List[str]:
        """Извлекает ссылки на JS файлы"""
        scripts = []
        
        for script in soup.find_all('script', src=True):
            src = urljoin(current_url, script['src'])
            scripts.append(src)
        
        return scripts
    
    def _extract_stylesheets(self, soup: BeautifulSoup, current_url: str) -> List[str]:
        """Извлекает ссылки на CSS файлы"""
        stylesheets = []
        
        for link in soup.find_all('link', rel='stylesheet', href=True):
            href = urljoin(current_url, link['href'])
            stylesheets.append(href)
        
        return stylesheets
