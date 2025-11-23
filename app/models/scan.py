import enum
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from enums import Lang
from .base import Base, dt, LabeledEnumMixin


class ScanStatusEnum(LabeledEnumMixin, enum.IntEnum):
    PENDING = 1
    RUNNING = 2
    COMPLETED = 3
    FAILED = 4
    
    @classmethod
    def labels(cls, lang = Lang.RU):
        if lang == Lang.ENG:
            return {
                cls.PENDING: 'Pending',
                cls.RUNNING: 'Running',
                cls.COMPLETED: 'Completed',
                cls.FAILED: 'Failed'
            }
        return {
            cls.PENDING: 'Ожидает начала',
            cls.RUNNING: 'В работе',
            cls.COMPLETED: 'Завершен',
            cls.FAILED: 'Ошибка'
        }


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    target_url = Column(String(512), nullable=False)
    status = Column(Integer, nullable=False, default=ScanStatusEnum.PENDING)
    created_at = Column(dt(), server_default=func.now())
    completed_at = Column(dt(), nullable=True)
    
    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    
    @property
    def status_enum(self) -> ScanStatusEnum:
        return ScanStatusEnum(self.status)
