from pathlib import Path
import json
import os
import shutil
import subprocess
import time
from urllib.parse import urlencode
from uuid import uuid4

from .models import EndpointTestResult, ExecutionResult

class SandboxPolicyError(ValueError):
    pass

class SandboxController:
    """MVP guardrail: Docker execution and external targets are disabled."""
    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self.allowed_target = (self.workspace_root / "mock-targets" / "vulnerable-node-app").resolve()

    def validate_target(self, requested_path: str) -> Path:
        candidate = (self.workspace_root / requested_path).resolve()
        if candidate != self.allowed_target:
            raise SandboxPolicyError("MVP policy only permits mock-targets/vulnerable-node-app. External repositories are not enabled.")
        if not candidate.is_dir():
            raise SandboxPolicyError("The bundled mock target is missing.")
        return candidate

    def run_mock_validation(self, requested_path: str, execution_authorized: bool) -> ExecutionResult:
        """Run one bounded local validation case in a disposable Docker container.

        This deliberately supports only the bundled target. The runtime has no
        outbound network access and is removed regardless of success or failure.
        """
        if not execution_authorized:
            raise SandboxPolicyError("Explicit Docker execution authorization is required.")
        target = self.validate_target(requested_path)
        docker = self._docker_path()
        image = "hydrabench/mock-target:latest"
        self._run([docker, "build", "--pull", "--tag", image, "--file", str(self.workspace_root / "backend" / "Dockerfile.sandbox"), str(target)], timeout=180)
        container = f"hydrabench-{uuid4().hex[:12]}"
        policy = "network=none; read-only rootfs; tmpfs=/tmp; cap-drop=ALL; no-new-privileges; memory=256m; cpus=0.5; pids=64"
        start = [docker, "run", "--detach", "--name", container, "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "256m", "--cpus", "0.5", "--pids-limit", "64", image]
        try:
            self._run(start, timeout=30)
            time.sleep(1.5)
            probe = """const http=require('http');const request=http.request({host:'127.0.0.1',port:3100,path:'/api/v1/checkout',method:'POST',headers:{'Content-Type':'application/json'}},response=>{let body='';response.on('data',chunk=>body+=chunk);response.on('end',()=>console.log(JSON.stringify({status:response.statusCode,body})));});request.on('error',error=>{console.error(error.message);process.exit(2)});request.end();"""
            outcome = self._run([docker, "exec", container, "node", "-e", probe], timeout=20)
            data = json.loads(outcome.stdout.strip())
            logs = self._run([docker, "logs", container], timeout=20).stdout.strip()
            status = "PASSED" if data["status"] == 400 else "VULNERABILITY_DETECTED"
            return ExecutionResult(status=status, test_name="POST /api/v1/checkout without a body", http_status=data["status"], logs=logs[-4_000:], sandbox_policy=policy)
        finally:
            subprocess.run([docker, "rm", "--force", container], capture_output=True, text=True, timeout=30, check=False)

    def run_repository_validation(self, requested_path: str, execution_authorized: bool, test_cases: list[dict] | None = None, on_result=None) -> ExecutionResult:
        if not execution_authorized:
            raise SandboxPolicyError("Explicit Docker execution authorization is required.")
        root = self._validate_repository(requested_path)
        profile_root = self._node_project(root)
        if not profile_root:
            raise SandboxPolicyError("Unsupported runtime. HydraBench currently executes Node projects with package.json, package-lock.json, and an npm start script.")
        from .repository import RepositoryMapper
        report = RepositoryMapper(self.workspace_root).analyze(str(root.relative_to(self.workspace_root)), True)
        endpoints = test_cases or [{"name": f"{route.method} {route.path}", "method": route.method, "path": route.path, "expected_status_family": "2xx/4xx", "query": {}, "body": {}} for route in report.routes[:30]]
        if not endpoints:
            raise SandboxPolicyError("No HTTP routes were found to validate.")
        context = self._sanitized_context(profile_root)
        docker = self._docker_path(); image = f"hydrabench/node-runner:{uuid4().hex[:12]}"; container = f"hydrabench-{uuid4().hex[:12]}"
        policy = "network=none; read-only rootfs; tmpfs=/tmp; cap-drop=ALL; no-new-privileges; memory=256m; cpus=0.5; pids=64"
        try:
            self._run([docker, "build", "--tag", image, "--file", str(self.workspace_root / "backend" / "Dockerfile.node-sandbox"), str(context)], timeout=240)
            self._run([docker, "run", "--detach", "--name", container, "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "256m", "--cpus", "0.5", "--pids-limit", "64", "--env", "PORT=3100", image], timeout=30)
            self._wait_for_node_server(docker, container)
            probe = """const http=require('http');const spec=JSON.parse(process.argv[1]);const raw=spec.raw_body||'';const jsonBody=Object.keys(spec.body||{}).length?JSON.stringify(spec.body):'';const payload=raw||jsonBody;const headers={...(spec.headers||{})};if(payload){if(!headers['Content-Type'])headers['Content-Type']='application/json';headers['Content-Length']=Buffer.byteLength(payload);}const request=http.request({host:'127.0.0.1',port:3100,path:spec.path,method:spec.method,headers},response=>{response.resume();response.on('end',()=>{const actual=`${Math.floor(response.statusCode/100)}xx`;const expected=spec.expected_status_family||'2xx/4xx';const matches=expected.split('/').includes(actual);const outcome=matches?'PASSED':response.statusCode>=500?'VULNERABILITY_DETECTED':'EXPECTATION_FAILED';console.log(JSON.stringify({...spec,http_status:response.statusCode,outcome}));});});request.on('error',()=>console.log(JSON.stringify({...spec,http_status:null,outcome:'UNREACHABLE'})));if(payload)request.write(payload);request.end();"""
            results: list[EndpointTestResult] = []
            for index, case in enumerate(endpoints, start=1):
                query = case.get("query") or {}
                path = case["path"] + (("?" + urlencode(query)) if query else "")
                spec = {"name": case.get("name", f"Test {index}"), "method": case["method"].upper(), "path": path, "headers": case.get("headers") or {}, "body": case.get("body") or {}, "raw_body": case.get("raw_body") or "", "expected_status_family": case.get("expected_status_family", "2xx/4xx")}
                outcome = self._run([docker, "exec", container, "node", "-e", probe, json.dumps(spec)], timeout=20)
                item = EndpointTestResult(**json.loads(outcome.stdout.strip()))
                results.append(item)
                if on_result:
                    on_result(item)
            logs = self._run([docker, "logs", container], timeout=20).stdout.strip()
            detected = sum(item.outcome == "VULNERABILITY_DETECTED" for item in results)
            return ExecutionResult(status="VULNERABILITIES_DETECTED" if detected else "COMPLETED", test_name=f"{len(results)} discovered route validations", http_status=None, logs=logs[-4_000:], sandbox_policy=policy, endpoint_results=results)
        finally:
            subprocess.run([docker, "rm", "--force", container], capture_output=True, text=True, timeout=30, check=False)
            subprocess.run([docker, "image", "rm", "--force", image], capture_output=True, text=True, timeout=30, check=False)
            shutil.rmtree(context, ignore_errors=True)

    def _validate_repository(self, requested_path: str) -> Path:
        candidate = (self.workspace_root / requested_path).resolve()
        try:
            candidate.relative_to(self.workspace_root)
        except ValueError as error:
            raise SandboxPolicyError("Repository path must remain inside the HydraBench workspace.") from error
        if not candidate.is_dir():
            raise SandboxPolicyError("Repository directory was not found.")
        return candidate

    @staticmethod
    def _node_project(root: Path) -> Path | None:
        for manifest in root.rglob("package.json"):
            if any(part in {"node_modules", ".git", ".next"} for part in manifest.parts):
                continue
            try:
                package = json.loads(manifest.read_text(encoding="utf-8"))
                if package.get("scripts", {}).get("start") and (manifest.parent / "package-lock.json").is_file():
                    return manifest.parent
            except (OSError, ValueError):
                continue
        return None

    def _sanitized_context(self, root: Path) -> Path:
        destination = self.workspace_root / ".hydrabench" / "contexts" / uuid4().hex
        def ignore(directory: str, names: list[str]) -> set[str]:
            return {name for name in names if name in {"node_modules", ".git", ".next", ".env"} or name.startswith(".env.")}
        shutil.copytree(root, destination, ignore=ignore)
        return destination

    def _wait_for_node_server(self, docker: str, container: str) -> None:
        readiness_probe = """const http=require('http');const request=http.get({host:'127.0.0.1',port:3100,path:'/'},response=>{response.resume();response.on('end',()=>process.exit(0));});request.on('error',()=>process.exit(1));request.setTimeout(1000,()=>{request.destroy();process.exit(1)});"""
        for _ in range(20):
            check = subprocess.run([docker, "exec", container, "node", "-e", readiness_probe], capture_output=True, text=True, timeout=5, env={**os.environ, "PATH": str(Path(docker).parent) + os.pathsep + os.environ.get("PATH", "")})
            if check.returncode == 0:
                return
            time.sleep(0.5)
        raise SandboxPolicyError("Application did not become ready within 10 seconds. Review the sandbox startup log.")

    @staticmethod
    def _run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        docker_directory = str(Path(command[0]).parent)
        if docker_directory not in environment.get("PATH", "").split(os.pathsep):
            environment["PATH"] = docker_directory + os.pathsep + environment.get("PATH", "")
        try:
            return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=True, env=environment)
        except subprocess.CalledProcessError as error:
            message = error.stderr.strip() or error.stdout.strip() or "Docker command failed."
            raise SandboxPolicyError(message) from error
        except subprocess.TimeoutExpired as error:
            raise SandboxPolicyError("Docker operation exceeded its time limit.") from error

    @staticmethod
    def _docker_path() -> str:
        configured = os.getenv("DOCKER_PATH")
        candidates = [configured, r"C:\Program Files\Docker\Docker\resources\bin\docker.exe", "docker"]
        for candidate in candidates:
            if candidate and (candidate == "docker" or Path(candidate).is_file()):
                return candidate
        raise SandboxPolicyError("Docker CLI was not found.")
