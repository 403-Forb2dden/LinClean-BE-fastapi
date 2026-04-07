from typing import Any

from pydantic import BaseModel, ConfigDict


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str


class ErrorResponse(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None
    request_id: str | None = None
