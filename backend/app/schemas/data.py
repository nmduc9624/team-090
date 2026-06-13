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
