from sqlalchemy.orm import declarative_base
from sqlalchemy import DateTime
from enums import Lang
from config import cur_lang


Base = declarative_base()  # базовая модель


def dt(tz: bool = True):
    return DateTime(tz)


class LabeledEnumMixin:
    @classmethod
    def labels(cls, lang: Lang = Lang.RU) -> dict:
        raise NotImplementedError
    
    @property
    def label(self) -> str:
        return self.labels(cur_lang.get() or Lang.RU)[self]
    
    @property
    def syslabel(self) -> str:
        return self.labels(Lang.ENG)[self]
