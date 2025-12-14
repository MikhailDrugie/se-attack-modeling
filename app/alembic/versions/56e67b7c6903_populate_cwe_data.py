"""populate_cwe_data

Revision ID: 56e67b7c6903
Revises: 9e4a8ae1a7c9
Create Date: 2025-12-14 20:12:08.327461

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '56e67b7c6903'
down_revision: Union[str, Sequence[str], None] = '9e4a8ae1a7c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    op.execute("""
        INSERT INTO cwe (id, name, description, severity, remediation, "references", owasp_mapping) VALUES
        ('CWE-79', 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)', 
         'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page.',
         'HIGH',
         '- Validate all input using allowlists
- Encode output for appropriate context
- Use Content Security Policy (CSP)
- Use HTTPOnly and Secure flags on cookies
- Use modern frameworks with auto-escaping',
         '["https://cwe.mitre.org/data/definitions/79.html", "https://owasp.org/www-community/attacks/xss/"]',
         '["A03:2021 - Injection", "A07:2017 - XSS"]'),
        
        ('CWE-89', 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
         'The software constructs all or part of an SQL command using externally-influenced input without proper neutralization.',
         'CRITICAL',
         '- Use parameterized queries (prepared statements)
- Use stored procedures
- Validate input using allowlists
- Apply least privilege to database accounts
- Use ORM frameworks',
         '["https://cwe.mitre.org/data/definitions/89.html", "https://owasp.org/www-community/attacks/SQL_Injection"]',
         '["A03:2021 - Injection", "A1:2017 - Injection"]'),
        
        ('CWE-352', 'Cross-Site Request Forgery (CSRF)',
         'The web application does not sufficiently verify whether a request was intentionally provided by the user.',
         'HIGH',
         '- Generate unique anti-CSRF tokens for each session
- Validate tokens on state-changing operations
- Use SameSite cookie attribute
- Check Origin and Referer headers
- Require re-authentication for sensitive actions',
         '["https://cwe.mitre.org/data/definitions/352.html", "https://owasp.org/www-community/attacks/csrf"]',
         '["A01:2021 - Broken Access Control"]'),
        
        ('CWE-307', 'Improper Restriction of Excessive Authentication Attempts',
         'The software does not implement sufficient measures to prevent multiple failed authentication attempts.',
         'HIGH',
         '- Implement account lockout after N failed attempts
- Add exponential backoff delays
- Require CAPTCHA after multiple failures
- Implement rate limiting by IP and username
- Use Multi-Factor Authentication (MFA)
- Monitor and alert on suspicious patterns',
         '["https://cwe.mitre.org/data/definitions/307.html"]',
         '["A07:2021 - Identification and Authentication Failures"]'),
        
        ('CWE-200', 'Exposure of Sensitive Information to an Unauthorized Actor',
         'The product exposes sensitive information to an actor that is not authorized to have access.',
         'MEDIUM',
         '- Disable debug mode in production
- Remove version information from headers
- Configure custom error pages
- Restrict access to sensitive directories/files
- Use proper access controls',
         '["https://cwe.mitre.org/data/definitions/200.html"]',
         '["A01:2021 - Broken Access Control"]'),
        
        ('CWE-548', 'Exposure of Information Through Directory Listing',
         'A directory listing is inappropriately exposed, yielding potentially sensitive information.',
         'MEDIUM',
         '- Disable directory listing in web server configuration
- Add index.html to all directories
- Configure proper access controls
- Remove sensitive files from web-accessible directories',
         '["https://cwe.mitre.org/data/definitions/548.html"]',
         '["A05:2021 - Security Misconfiguration"]'),
        
        ('CWE-16', 'Configuration',
         'Weaknesses in this category are typically introduced during the configuration of the software.',
         'MEDIUM',
         '- Follow security hardening guides
- Use secure defaults
- Regular security audits
- Automated configuration validation
- Principle of least privilege',
         '["https://cwe.mitre.org/data/definitions/16.html"]',
         '["A05:2021 - Security Misconfiguration"]'),
        
        ('CWE-94', 'Improper Control of Generation of Code (Code Injection)',
         'The software constructs code segments using externally-influenced input without proper neutralization.',
         'CRITICAL',
         '- Never use eval() or exec() with user input
- Use safe alternatives (ast.literal_eval in Python)
- Validate and sanitize all input
- Use allowlists for permitted values
- Implement code review and static analysis',
         '["https://cwe.mitre.org/data/definitions/94.html"]',
         '["A03:2021 - Injection"]'),
        
        ('CWE-78', 'Improper Neutralization of Special Elements used in an OS Command (Command Injection)',
         'The software constructs OS commands using externally-influenced input without proper neutralization.',
         'CRITICAL',
         '- Avoid calling OS commands with user input
- Use language-specific APIs instead of shell commands
- Validate input using strict allowlists
- Use parameterized APIs
- Run with minimal privileges',
         '["https://cwe.mitre.org/data/definitions/78.html"]',
         '["A03:2021 - Injection"]'),
        
        ('CWE-502', 'Deserialization of Untrusted Data',
         'The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.',
         'CRITICAL',
         '- Avoid deserializing untrusted data
- Use safe serialization formats (JSON instead of Pickle)
- Implement integrity checks
- Use allowlists for permitted classes
- Run deserialization in sandboxed environment',
         '["https://cwe.mitre.org/data/definitions/502.html"]',
         '["A08:2021 - Software and Data Integrity Failures"]'),
        
        ('CWE-UNKNOWN', 'Unknown or Unclassified Weakness',
         'This vulnerability has not been mapped to a specific CWE classification yet.',
         'VARIES',
         'Review the vulnerability description and apply appropriate security measures based on the specific context.',
         '[]',
         '[]')
    ON CONFLICT (id) DO NOTHING;
    """)


def downgrade():
    op.execute("DELETE FROM cwe WHERE id IN ('CWE-79', 'CWE-89', 'CWE-352', 'CWE-307', 'CWE-200', 'CWE-548', 'CWE-16', 'CWE-94', 'CWE-78', 'CWE-502', 'CWE-UNKNOWN')")
