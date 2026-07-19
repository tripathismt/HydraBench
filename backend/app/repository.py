from __future__ import annotations

import re
import json
import shutil
import stat
import zipfile
from io import BytesIO
from pathlib import Path
from uuid import uuid4

from .models import ApiRoute, RepositoryAnalysis, UploadedRepository

IGNORED_DIRECTORIES = {".git", ".next", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
SUPPORTED_SUFFIXES = {".js", ".ts", ".jsx", ".tsx", ".py"}
MAX_FILES = 1_000
MAX_FILE_BYTES = 1_000_000
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_ARCHIVE_FILES = 5_000
MAX_EXTRACTED_BYTES = 200 * 1024 * 1024

EXPRESS_ROUTE = re.compile(r"(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*[`\"']([^`\"']+)", re.IGNORECASE)
FASTAPI_ROUTE = re.compile(r"@(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*[`\"']([^`\"']+)", re.IGNORECASE)
REQUIRE_IMPORT = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['\"](\.[^'\"]+)['\"]\s*\)")
USE_MOUNT = re.compile(r"(?:app|router)\.use\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\w+)")


class RepositoryPolicyError(ValueError):
    pass


class RepositoryMapper:
    """Read-only, bounded local repository mapper.

    Execution is deliberately separate from mapping. A repository is never run on
    the host; a future Docker controller must enforce an explicit execution gate.
    """

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()

    def analyze(self, requested_path: str, authorization_confirmed: bool) -> RepositoryAnalysis:
        if not authorization_confirmed:
            raise RepositoryPolicyError("Confirm authorization before HydraBench reads a repository.")
        root = self._validate_path(requested_path)
        routes = self._node_routes(root)
        files_scanned = 0
        for path in self._source_files(root):
            files_scanned += 1
            content = path.read_text(encoding="utf-8", errors="replace")
            if not routes:
                routes.extend(self._routes_in_file(path, content, root))
        unique_routes = {(route.method, route.path, route.source_file, route.line): route for route in routes}
        return RepositoryAnalysis(
            repository_path=str(root.relative_to(self.workspace_root)),
            files_scanned=files_scanned,
            routes=sorted(unique_routes.values(), key=lambda route: (route.path, route.method)),
            execution_status="BLOCKED",
            execution_note="Static mapping completed. Test execution is disabled until Docker sandboxing is installed and an execution authorization is supplied.",
        )

    def source_context(self, requested_path: str, max_characters: int = 120_000) -> str:
        root = self._validate_path(requested_path)
        parts: list[str] = []
        remaining = max_characters
        for path in self._source_files(root):
            content = path.read_text(encoding="utf-8", errors="replace")
            entry = f"\n\n--- {path.relative_to(root)} ---\n{content}"
            if len(entry) > remaining:
                parts.append(entry[:remaining])
                break
            parts.append(entry)
            remaining -= len(entry)
            if remaining <= 0:
                break
        return "".join(parts)

    def _node_routes(self, root: Path) -> list[ApiRoute]:
        manifests = [path for path in root.rglob("package.json") if not any(part in IGNORED_DIRECTORIES for part in path.parts)]
        if not manifests:
            return []
        try:
            import json
            manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
            entry = manifests[0].parent / manifest.get("main", "server.js")
        except (OSError, ValueError, TypeError):
            return []
        if not entry.is_file():
            return []
        routes: list[ApiRoute] = []
        visited: set[tuple[Path, str]] = set()
        def walk(path: Path, prefix: str) -> None:
            key = (path, prefix)
            if key in visited or not path.is_file():
                return
            visited.add(key)
            content = path.read_text(encoding="utf-8", errors="replace")
            for route in self._routes_in_file(path, content, root):
                route.path = _join_path(prefix, route.path)
                routes.append(route)
            imports = {name: self._resolve_require(path, relative) for name, relative in REQUIRE_IMPORT.findall(content)}
            for mount, variable in USE_MOUNT.findall(content):
                dependency = imports.get(variable)
                if dependency:
                    walk(dependency, _join_path(prefix, mount))
        walk(entry, "")
        return routes

    @staticmethod
    def _resolve_require(source: Path, relative: str) -> Path | None:
        base = (source.parent / relative).resolve()
        for candidate in (base, base.with_suffix(".js"), base / "index.js"):
            if candidate.is_file():
                return candidate
        return None

    def store_upload(self, archive_name: str, archive_data: bytes, authorization_confirmed: bool) -> UploadedRepository:
        if not authorization_confirmed:
            raise RepositoryPolicyError("Confirm authorization before HydraBench stores an uploaded repository.")
        if not archive_name.lower().endswith(".zip"):
            raise RepositoryPolicyError("Upload a .zip archive containing the repository source.")
        if len(archive_data) > MAX_ARCHIVE_BYTES:
            raise RepositoryPolicyError("Archive exceeds the 50 MB upload limit.")
        try:
            archive = zipfile.ZipFile(BytesIO(archive_data))
        except zipfile.BadZipFile as error:
            raise RepositoryPolicyError("Uploaded file is not a valid ZIP archive.") from error
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_FILES:
            raise RepositoryPolicyError("Archive contains too many files.")
        total_uncompressed = sum(info.file_size for info in infos)
        if total_uncompressed > MAX_EXTRACTED_BYTES:
            raise RepositoryPolicyError("Archive expands beyond the 200 MB extraction limit.")
        destination = self.workspace_root / ".hydrabench" / "uploads" / uuid4().hex
        destination.mkdir(parents=True, exist_ok=False)
        files_extracted = 0
        try:
            for info in infos:
                relative = Path(info.filename)
                if not info.filename or relative.is_absolute() or ".." in relative.parts or stat.S_ISLNK(info.external_attr >> 16):
                    raise RepositoryPolicyError("Archive contains an unsafe path or symbolic link.")
                output = (destination / relative).resolve()
                if destination not in output.parents and output != destination:
                    raise RepositoryPolicyError("Archive entry escapes the staging directory.")
                if info.is_dir():
                    output.mkdir(parents=True, exist_ok=True)
                    continue
                output.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, output.open("wb") as target:
                    shutil.copyfileobj(source, target, length=64 * 1024)
                files_extracted += 1
        except Exception:
            shutil.rmtree(destination, ignore_errors=True)
            raise
        repository_root = self._archive_root(destination)
        uploaded = UploadedRepository(repository_path=str(repository_root.relative_to(self.workspace_root)), archive_name=Path(archive_name).name, files_extracted=files_extracted, bytes_extracted=total_uncompressed)
        active = self.workspace_root / ".hydrabench" / "active-repository.json"
        active.parent.mkdir(parents=True, exist_ok=True)
        active.write_text(json.dumps(uploaded.model_dump()), encoding="utf-8")
        return uploaded

    def latest_upload(self) -> UploadedRepository:
        active = self.workspace_root / ".hydrabench" / "active-repository.json"
        if active.is_file():
            try:
                uploaded = UploadedRepository.model_validate_json(active.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                raise RepositoryPolicyError("The saved repository selection is invalid.") from error
        else:
            uploads = self.workspace_root / ".hydrabench" / "uploads"
            candidates = sorted((path for path in uploads.iterdir() if path.is_dir()), key=lambda path: path.stat().st_mtime, reverse=True) if uploads.is_dir() else []
            if not candidates:
                raise RepositoryPolicyError("No uploaded repository is available yet.")
            repository_root = self._archive_root(candidates[0])
            files = [path for path in repository_root.rglob("*") if path.is_file()]
            uploaded = UploadedRepository(repository_path=str(repository_root.relative_to(self.workspace_root)), archive_name=repository_root.name, files_extracted=len(files), bytes_extracted=sum(path.stat().st_size for path in files))
            active.parent.mkdir(parents=True, exist_ok=True)
            active.write_text(json.dumps(uploaded.model_dump()), encoding="utf-8")
        self._validate_path(uploaded.repository_path)
        return uploaded

    @staticmethod
    def _archive_root(destination: Path) -> Path:
        children = [path for path in destination.iterdir() if path.name not in {"__MACOSX", ".DS_Store"}]
        return children[0] if len(children) == 1 and children[0].is_dir() else destination

    def _validate_path(self, requested_path: str) -> Path:
        candidate = Path(requested_path)
        resolved = candidate.resolve() if candidate.is_absolute() else (self.workspace_root / candidate).resolve()
        try:
            resolved.relative_to(self.workspace_root)
        except ValueError as error:
            raise RepositoryPolicyError("Repository path must be inside the HydraBench workspace.") from error
        if not resolved.is_dir():
            raise RepositoryPolicyError("Repository directory was not found.")
        return resolved

    def _source_files(self, root: Path):
        count = 0
        for path in root.rglob("*"):
            if any(part in IGNORED_DIRECTORIES for part in path.parts) or not path.is_file() or path.suffix.lower() not in SUPPORTED_SUFFIXES:
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            count += 1
            if count > MAX_FILES:
                return
            yield path

    def _routes_in_file(self, path: Path, content: str, root: Path) -> list[ApiRoute]:
        routes: list[ApiRoute] = []
        for pattern in (EXPRESS_ROUTE, FASTAPI_ROUTE):
            for match in pattern.finditer(content):
                method, route_path = match.groups()
                routes.append(ApiRoute(
                    method=method.upper(), path=route_path, source_file=str(path.relative_to(root)),
                    line=content.count("\n", 0, match.start()) + 1,
                    test_cases=self._test_cases(method.upper()),
                ))
        return routes

    @staticmethod
    def _test_cases(method: str) -> list[str]:
        cases = ["Valid request returns the documented success status", "Missing required request fields return a validation error", "Malformed JSON is rejected safely"]
        if method in {"POST", "PUT", "PATCH"}:
            cases.append("Unexpected field types return a validation error")
        return cases


def _join_path(prefix: str, route: str) -> str:
    joined = "/".join(part.strip("/") for part in (prefix, route) if part and part != "/")
    return "/" + joined if joined else "/"
