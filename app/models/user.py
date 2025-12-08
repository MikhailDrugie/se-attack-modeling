import enum
from sqlalchemy import Column, Integer, String
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from enums import Lang
from .base import Base, dt, LabeledEnumMixin


class UserStatusEnum(LabeledEnumMixin, enum.IntEnum):
    ACTIVE = 1
    DISABLED = 2
    BANNED = 3
    SOFT_DELETE = 4
    
    @classmethod
    def labels(cls, lang=Lang.RU) -> dict[int, str]:
        if lang == Lang.ENG:
            return {
                cls.ACTIVE: 'Active',
                cls.DISABLED: 'Disabled',
                cls.BANNED: 'Banned',
                cls.SOFT_DELETE: 'Deleted'
            }
        return {
            cls.ACTIVE: 'Активен',
            cls.DISABLED: 'Отключен',
            cls.BANNED: 'Заблокирован',
            cls.SOFT_DELETE: 'Удален'
        }
    
    
class UserRoleEnum(LabeledEnumMixin, enum.IntEnum):
    DEV = 1
    ANALYST = 2
    ADMIN = 3
    
    @classmethod
    def labels(cls, lang=Lang.RU) -> dict[int, str]:
        if lang == Lang.ENG:
            return {
                cls.DEV: "Developer",
                cls.ANALYST: "Security Analyst",
                cls.ADMIN: "Administrator"
            }
        return {
            cls.DEV: "Разработчик",
            cls.ANALYST: "Аналитик Безопасности",
            cls.ADMIN: "Администратор"
        }


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    status = Column(Integer, default=UserStatusEnum.ACTIVE, nullable=False)
    role = Column(Integer, default=UserRoleEnum.DEV, nullable=False)
    
    created_at = Column(dt(), server_default=func.now())
    updated_at = Column(dt(), server_default=func.now(), server_onupdate=func.now())
    
    scans = relationship("Scan", back_populates="user")
    
    @property
    def role_enum(self) -> UserRoleEnum:
        return UserRoleEnum(self.role)
    
    @property
    def status_enum(self) -> UserStatusEnum:
        return UserStatusEnum(self.status)
