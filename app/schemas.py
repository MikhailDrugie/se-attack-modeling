from pydantic import BaseModel, HttpUrl, computed_field
from typing import List, Optional
from datetime import datetime
from models import UserStatusEnum, UserRoleEnum, ScanStatusEnum, SeverityEnum, VulnerabilityTypesEnum


# --- User Schemas ---
class UserBase(BaseModel):
    username: str
    role: UserRoleEnum = UserRoleEnum.DEV

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int
    status: UserStatusEnum
    created_at: datetime
    
    @computed_field
    @property
    def is_active(self) -> bool:
        return self.status == UserStatusEnum.ACTIVE

    class Config:
        from_attributes = True

class UserBrief(UserBase):
    id: int
    
    class Config:
        from_attributes = True

# --- CWE ---
class CWEResponse(BaseModel):
    id: str
    name: str
    description: str
    extended_description: Optional[str]
    severity: str
    remediation: str
    references: Optional[List[str]]
    owasp_mapping: Optional[List[str]]
    
    class Config:
        from_attributes = True

# --- Vulnerability Schemas ---
class VulnerabilitySchema(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    severity: SeverityEnum
    url_path: str
    type: VulnerabilityTypesEnum
    cwe_id: Optional[str]
    cwe: Optional[CWEResponse] = None 

    class Config:
        from_attributes = True

# --- Scan Schemas ---
class ScanBase(BaseModel):
    target_url: HttpUrl  # validate through pydantic

class ScanCreate(ScanBase):
    debug: bool = False

class ScanListItem(ScanBase):
    id: int
    status: ScanStatusEnum
    created_at: datetime
    user: UserBrief
    vulnerabilities_amount: int
    
    class Config:
        from_attributes = True

class ScanResponse(ScanBase):
    id: int
    status: ScanStatusEnum
    created_at: datetime
    completed_at: Optional[datetime] = None
    user: UserBrief
    vulnerabilities: List[VulnerabilitySchema] = []

    class Config:
        from_attributes = True
