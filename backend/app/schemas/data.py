from pydantic import BaseModel


class QueryTemplate(BaseModel):
    name: str
    platform: str
    path: str
    content: str


class DataFile(BaseModel):
    name: str
    path: str
    content: str

class AlertCatalogItem(BaseModel):
    slug: str
    alert_name: str
    alert_source: str
    severity: str
    category: str
    status: str


class SampleReport(BaseModel):
    slug: str
    alert_name: str
    alert_source: str
    severity: str
    category: str
    content: str
