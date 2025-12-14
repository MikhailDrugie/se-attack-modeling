from sqlalchemy import Column, String, Text, JSON
from sqlalchemy.sql import func, select
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship

from .base import Base


class CWE(Base):
    __tablename__ = "cwe"
    
    id = Column(String(64), primary_key=True)  # "CWE-79"
    name = Column(String(500))
    description = Column(Text)
    extended_description = Column(Text, nullable=True)
    severity = Column(String(20))
    remediation = Column(Text)
    references = Column(JSON)  # ["url1", "url2"]
    owasp_mapping = Column(JSON, nullable=True)  # ["A03:2021"]
    
    # Связь с уязвимостями
    vulnerabilities = relationship("Vulnerability", back_populates="cwe")
