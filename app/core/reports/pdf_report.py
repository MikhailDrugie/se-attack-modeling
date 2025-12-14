from weasyprint import HTML, CSS
from pathlib import Path
from typing import List
from models.scan import Scan
from models.vulnerability import Vulnerability
from .html_report import HTMLReportGenerator


class PDFReportGenerator:
    """Генератор PDF отчётов"""
    
    def __init__(self):
        self.html_generator = HTMLReportGenerator()
    
    def generate(self, scan: Scan, vulnerabilities: List[Vulnerability]) -> bytes:
        """
        Генерирует PDF отчёт из HTML
        
        Args:
            scan: Объект Scan
            vulnerabilities: Список Vulnerability
            
        Returns:
            bytes: PDF контент
        """
        # Генерируем HTML
        html_content = self.html_generator.generate(scan, vulnerabilities)
        
        # Дополнительные стили для печати
        print_css = CSS(string="""
            @page {
                size: A4;
                margin: 2cm;
            }
            
            body {
                font-size: 10pt;
            }
            
            .vulnerability {
                page-break-inside: avoid;
            }
            
            .header {
                page-break-after: avoid;
            }
        """)
        
        # Конвертируем в PDF
        pdf_bytes = HTML(string=html_content).write_pdf(stylesheets=[print_css])
        
        return pdf_bytes
