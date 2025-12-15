import os
import re
import zipfile
import tarfile
import tempfile
import shutil
from typing import List, Dict
from pathlib import Path

from .dto import AnalyzerResult, VulnerabilityDTO
from models.vulnerability import VulnerabilityTypesEnum, SeverityEnum
from utils.logging import app_logger


class SASTAnalyzer:
    """Статический анализ кода из архива"""
    
    def __init__(self, archive_path: str):
        self.archive_path = archive_path
        self.temp_dir = None
        self.result = AnalyzerResult(analyzer_name="SAST")
        
    def get_dangerous_patterns(self) -> Dict[str, List[tuple]]:
        """
        Опасные паттерны для разных языков
        Формат: (regex, description, severity, cwe_id)
        """
        return {
            'python': [
                (r'eval\s*\(', "Code injection via eval()", SeverityEnum.CRITICAL, "CWE-94"),
                (r'exec\s*\(', "Code injection via exec()", SeverityEnum.CRITICAL, "CWE-94"),
                (r'__import__\s*\(', "Dynamic import vulnerability", SeverityEnum.HIGH, "CWE-94"),
                (r'pickle\.loads?\s*\(', "Unsafe deserialization", SeverityEnum.CRITICAL, "CWE-502"),
                (r'\.execute\s*\([^?]*[\'"][^?]*%', "SQL injection (string formatting)", SeverityEnum.CRITICAL, "CWE-89"),
                (r'subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True', "Command injection", SeverityEnum.CRITICAL, "CWE-78"),
                (r'os\.system\s*\(', "Command injection via os.system", SeverityEnum.CRITICAL, "CWE-78"),
            ],
            'javascript': [
                (r'eval\s*\(', "Code injection via eval()", SeverityEnum.CRITICAL, "CWE-94"),
                (r'innerHTML\s*=', "Potential XSS via innerHTML", SeverityEnum.HIGH, "CWE-79"),
                (r'document\.write\s*\(', "Potential XSS via document.write", SeverityEnum.HIGH, "CWE-79"),
                (r'dangerouslySetInnerHTML', "React XSS vulnerability", SeverityEnum.HIGH, "CWE-79"),
                (r'new\s+Function\s*\(', "Code injection via Function constructor", SeverityEnum.CRITICAL, "CWE-94"),
                (r'setTimeout\s*\(\s*[\'"]', "Code injection via setTimeout", SeverityEnum.HIGH, "CWE-94"),
                (r'setInterval\s*\(\s*[\'"]', "Code injection via setInterval", SeverityEnum.HIGH, "CWE-94"),
            ],
            'php': [
                (r'eval\s*\(', "Code injection via eval()", SeverityEnum.CRITICAL, "CWE-94"),
                (r'\$_(GET|POST|REQUEST|COOKIE)\[', "Direct user input usage", SeverityEnum.MEDIUM, "CWE-20"),
                (r'mysql_query\s*\(\s*[\'"].*\$', "SQL injection (mysql)", SeverityEnum.CRITICAL, "CWE-89"),
                (r'mysqli_query\s*\(.*\$', "SQL injection (mysqli)", SeverityEnum.CRITICAL, "CWE-89"),
                (r'exec\s*\(', "Command injection via exec", SeverityEnum.CRITICAL, "CWE-78"),
                (r'system\s*\(', "Command injection via system", SeverityEnum.CRITICAL, "CWE-78"),
                (r'passthru\s*\(', "Command injection via passthru", SeverityEnum.CRITICAL, "CWE-78"),
                (r'shell_exec\s*\(', "Command injection via shell_exec", SeverityEnum.CRITICAL, "CWE-78"),
                (r'unserialize\s*\(', "Unsafe deserialization", SeverityEnum.HIGH, "CWE-502"),
            ],
            'java': [
                (r'Runtime\.getRuntime\(\)\.exec', "Command injection", SeverityEnum.CRITICAL, "CWE-78"),
                (r'Class\.forName', "Dynamic class loading", SeverityEnum.MEDIUM, "CWE-470"),
                (r'ObjectInputStream\.readObject', "Unsafe deserialization", SeverityEnum.CRITICAL, "CWE-502"),
            ],
            'csharp': [
                (r'Process\.Start', "Command injection", SeverityEnum.HIGH, "CWE-78"),
                (r'SqlCommand.*\+', "SQL injection (string concatenation)", SeverityEnum.CRITICAL, "CWE-89"),
                (r'BinaryFormatter\.Deserialize', "Unsafe deserialization", SeverityEnum.CRITICAL, "CWE-502"),
            ]
        }
    
    def _extract_archive(self) -> str:
        """Распаковывает архив во временную папку"""
        self.temp_dir = tempfile.mkdtemp(prefix="sast_scan_")
        
        try:
            if zipfile.is_zipfile(self.archive_path):
                with zipfile.ZipFile(self.archive_path, 'r') as zip_ref:
                    zip_ref.extractall(self.temp_dir)
                app_logger.info(f"[SAST] Extracted ZIP archive to {self.temp_dir}")
            elif tarfile.is_tarfile(self.archive_path):
                with tarfile.open(self.archive_path, 'r:*') as tar_ref:
                    tar_ref.extractall(self.temp_dir)
                app_logger.info(f"[SAST] Extracted TAR archive to {self.temp_dir}")
            else:
                raise ValueError("Unsupported archive format")
        except Exception as e:
            app_logger.error(f"[SAST] Failed to extract archive: {e}")
            raise
        
        return self.temp_dir
    
    def _find_source_files(self) -> List[tuple]:
        """
        Находит исходные файлы для анализа
        Returns: [(file_path, language), ...]
        """
        extensions = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'javascript',
            '.tsx': 'javascript',
            '.php': 'php',
            '.java': 'java',
            '.cs': 'csharp',
        }
        
        files = []
        for root, dirs, filenames in os.walk(self.temp_dir):
            # Игнорируем node_modules, venv, __pycache__
            dirs[:] = [d for d in dirs if d not in ['node_modules', 'venv', '.venv', '__pycache__', '.git']]
            
            for filename in filenames:
                ext = Path(filename).suffix.lower()
                if ext in extensions:
                    file_path = os.path.join(root, filename)
                    files.append((file_path, extensions[ext]))
        
        app_logger.info(f"[SAST] Found {len(files)} source files")
        return files
    
    def _scan_file(self, file_path: str, language: str) -> List[VulnerabilityDTO]:
        """Сканирует один файл"""
        vulnerabilities = []
        patterns = self.get_dangerous_patterns().get(language, [])
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            app_logger.error(f"[SAST] Failed to read {file_path}: {e}")
            return vulnerabilities
        
        # Относительный путь для отчёта
        relative_path = os.path.relpath(file_path, self.temp_dir)
        
        for pattern, description, severity, cwe_id in patterns:
            for line_num, line in enumerate(lines, start=1):
                if re.search(pattern, line, re.IGNORECASE):
                    vuln = VulnerabilityDTO(
                        name=f"SAST: {description}",
                        description=(
                            f"**File:** `{relative_path}`\n"
                            f"**Line:** {line_num}\n"
                            f"**Code:** `{line.strip()}`\n\n"
                            f"**Issue:** {description}\n\n"
                            f"**Risk:** This pattern indicates a potential security vulnerability. "
                            f"Manual review is required to confirm if it's exploitable.\n\n"
                            f"**Recommendation:**\n"
                            f"- Review the code context\n"
                            f"- Ensure user input is properly validated and sanitized\n"
                            f"- Use safe alternatives where possible\n"
                            f"- Apply principle of least privilege"
                        ),
                        vuln_type=VulnerabilityTypesEnum.SAST,
                        severity=severity,
                        url_path=f"{relative_path}:{line_num}",
                        parameter=language,
                        method="SAST",
                        evidence=line.strip(),
                        cwe_id=cwe_id
                    )
                    vulnerabilities.append(vuln)
                    
                    app_logger.warning(
                        f"[SAST] Found vulnerability in {relative_path}:{line_num} - {description}"
                    )
        
        return vulnerabilities
    
    def _cleanup(self):
        """Удаляет временные файлы"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
                app_logger.info(f"[SAST] Cleaned up temp directory {self.temp_dir}")
            except Exception as e:
                app_logger.error(f"[SAST] Failed to cleanup {self.temp_dir}: {e}")
    
    def analyze(self) -> AnalyzerResult:
        """Главный метод анализа"""
        import time
        start_time = time.time()
        
        try:
            # 1. Распаковываем
            self._extract_archive()
            
            # 2. Находим файлы
            source_files = self._find_source_files()
            self.result.tested_endpoints = len(source_files)
            
            # 3. Сканируем каждый файл
            for file_path, language in source_files:
                vulns = self._scan_file(file_path, language)
                self.result.vulnerabilities.extend(vulns)
            
            self.result.duration = time.time() - start_time
            
            app_logger.info(
                f"[SAST] Analysis complete: {len(self.result.vulnerabilities)} vulnerabilities found "
                f"in {len(source_files)} files ({self.result.duration:.2f}s)"
            )
            
        finally:
            # 4. Чистим временные файлы
            self._cleanup()
        
        return self.result
