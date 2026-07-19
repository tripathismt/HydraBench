from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

class SessionStatus(str, Enum):
    queued = "queued"
    mapping = "mapping"
    testing = "testing"
    analyzing = "analyzing"
    patching = "patching"
    verifying = "verifying"
    resolved = "resolved"
    failed = "failed"

class ScanRequest(BaseModel):
    target_path: str = Field(default="mock-targets/vulnerable-node-app")
    execution_authorized: bool = False
    model_authorized: bool = False


class RepositoryRequest(BaseModel):
    repository_path: str = Field(default="mock-targets/vulnerable-node-app")
    authorization_confirmed: bool = False


class ApiRoute(BaseModel):
    method: str
    path: str
    source_file: str
    line: int
    test_cases: list[str]


class RepositoryAnalysis(BaseModel):
    repository_path: str
    files_scanned: int
    routes: list[ApiRoute]
    execution_status: str
    execution_note: str


class UploadedRepository(BaseModel):
    repository_path: str
    archive_name: str
    files_extracted: int
    bytes_extracted: int


class ExecutionRequest(BaseModel):
    repository_path: str = "mock-targets/vulnerable-node-app"
    execution_authorized: bool = False


class ExecutionResult(BaseModel):
    status: str
    test_name: str
    http_status: int | None = None
    logs: str
    sandbox_policy: str
    endpoint_results: list["EndpointTestResult"] = []


class EndpointTestResult(BaseModel):
    name: str
    method: str
    path: str
    http_status: int | None = None
    outcome: str
    expected_status_family: str | None = None

class Event(BaseModel):
    type: str
    message: str
    status: SessionStatus
    timestamp: str

class Incident(BaseModel):
    id: str
    severity: str
    vector: str
    endpoint: str
    root_cause: str
    status: str
    patch_diff: str

class ScanSession(BaseModel):
    id: str
    target_path: str
    status: SessionStatus
    model_authorized: bool = False
    events: list[Event] = []
    incident: Incident | None = None
    report: dict[str, Any] | None = None
