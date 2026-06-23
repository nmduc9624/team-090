from pydantic import BaseModel, Field


class QueryTemplate(BaseModel):
    name: str
    platform: str
    path: str
    content: str
    metadata: dict[str, object] = Field(default_factory=dict)


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

