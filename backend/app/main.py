import asyncio
import os
from pathlib import Path
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from .models import ExecutionRequest, ExecutionResult, RepositoryAnalysis, RepositoryRequest, ScanRequest, ScanSession, UploadedRepository
from .orchestrator import Orchestrator
from .repository import RepositoryMapper, RepositoryPolicyError
from .sandbox import SandboxController, SandboxPolicyError

ROOT = Path(__file__).resolve().parents[2]
orchestrator = Orchestrator(SandboxController(ROOT))
repository_mapper = RepositoryMapper(ROOT)
app = FastAPI(title="HydraBench API", version="0.1.0")
allowed_origins = [origin.strip() for origin in os.getenv("HYDRABENCH_CORS_ORIGINS", "http://localhost:3000").split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_methods=["*"], allow_headers=["*"])

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "mock-target-only"}

@app.post("/sessions", response_model=ScanSession, status_code=202)
async def start_scan(request: ScanRequest) -> ScanSession:
    try:
        session = orchestrator.create_session(request.target_path, request.execution_authorized, request.model_authorized)
    except (SandboxPolicyError, ValueError) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    asyncio.create_task(orchestrator.run(session.id))
    return session


@app.post("/repositories/analyze", response_model=RepositoryAnalysis)
def analyze_repository(request: RepositoryRequest) -> RepositoryAnalysis:
    try:
        return repository_mapper.analyze(request.repository_path, request.authorization_confirmed)
    except RepositoryPolicyError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/repositories/upload", response_model=UploadedRepository)
async def upload_repository(archive: UploadFile = File(...), authorization_confirmed: bool = Form(False)) -> UploadedRepository:
    data = await archive.read(50 * 1024 * 1024 + 1)
    try:
        return repository_mapper.store_upload(archive.filename or "repository.zip", data, authorization_confirmed)
    except RepositoryPolicyError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.get("/repositories/latest", response_model=UploadedRepository)
def latest_repository() -> UploadedRepository:
    try:
        return repository_mapper.latest_upload()
    except RepositoryPolicyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.post("/sandbox/run-validation", response_model=ExecutionResult)
def run_validation(request: ExecutionRequest) -> ExecutionResult:
    try:
        return orchestrator.sandbox.run_repository_validation(request.repository_path, request.execution_authorized)
    except SandboxPolicyError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/sessions/reset", status_code=204)
def reset_sessions() -> None:
    """Remove only persisted dashboard-run state; uploaded repositories remain intact."""
    orchestrator.clear_latest()


@app.get("/sessions/latest", response_model=ScanSession)
def get_latest_session() -> ScanSession:
    """Restore the dashboard after a browser refresh during this local API run."""
    try:
        return orchestrator.latest()
    except KeyError as error:
        raise HTTPException(status_code=404, detail="No local scan session is available yet") from error


@app.get("/sessions/{session_id}", response_model=ScanSession)
def get_session(session_id: str) -> ScanSession:
    try:
        return orchestrator.get(session_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Unknown session") from error


@app.get("/sessions/{session_id}/events")
async def stream_session(session_id: str) -> StreamingResponse:
    """Push session snapshots to the dashboard until the run reaches a terminal state."""
    try:
        orchestrator.get(session_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Unknown session") from error

    async def event_source():
        event_count = -1
        while True:
            session = orchestrator.get(session_id)
            if event_count != len(session.events):
                event_count = len(session.events)
                yield f"data: {session.model_dump_json()}\n\n"
            if session.status in {"resolved", "failed"}:
                return
            await asyncio.sleep(0.35)

    return StreamingResponse(event_source(), media_type="text/event-stream")
