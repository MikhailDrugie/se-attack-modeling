from dataclasses import dataclass, field
from typing import Optional, Any
from enum import IntEnum


class FormMethods(IntEnum):
    GET = 1
    POST = 2
    PUT = 3
    PATCH = 4
    DELETE = 5

    @classmethod
    def find(cls, raw: str):
        return cls.__members__.get(raw, cls.POST)


class FieldType(IntEnum):
    TEXT = 1
    PASSWORD = 2
    EMAIL = 3
    CHECKBOX = 4
    RADIO = 5
    HIDDEN = 6
    SUBMIT = 7
    TEXTAREA = 8
    SELECT = 9
    FILE = 10
    UNKNOWN = -1
    
    @classmethod
    def find(cls, raw: str):
        return cls.__members__.get(raw, cls.UNKNOWN)


@dataclass
class FormField:
    name: str
    field_type: FieldType | int = FieldType.UNKNOWN
    value: Optional[str] = None
    required: bool = False
    placeholder: Optional[str] = None
    data: Optional[Any] = None


@dataclass
class Link:
    raw: str
    url: str
    query_params: dict[str, list[str] | str] = field(default_factory=dict)


@dataclass
class Form:
    action: Link
    method: FormMethods | int
    fields: list[FormField]
    form_id: Optional[str] = None
    form_class: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {f.name: f.value or '' for f in self.fields}


@dataclass
class ExtLink(Link):
    href: str = '' # raw href, deafults for correct inheritance 
    rel: Optional[str] = None
    anchor: Optional[str] = None


@dataclass
class Page:
    link: Link
    title: Optional[str] = None
    # navigating forward
    links: list[ExtLink] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    # other
    scripts: list[str] = field(default_factory=list)
    styles: list[str] = field(default_factory=list)
    meta_tags: list[str] = field(default_factory=list)
