import asyncio
from datetime import UTC, datetime
from uuid import uuid4
from pathlib import Path
from .models import Event, Incident, ScanSession, SessionStatus
from .sandbox import SandboxController

class Orchestrator:
    def __init__(self, sandbox: SandboxController) -> None:
        self.sandbox = sandbox
        self.sessions: dict[str, ScanSession] = {}
        self.session_snapshot = self.sandbox.workspace_root / ".hydrabench" / "latest-session.json"

    def create_session(self, target_path: str, execution_authorized: bool, model_authorized: bool) -> ScanSession:
        if not execution_authorized:
            raise ValueError("Explicit Docker execution authorization is required.")
        self.sandbox._validate_repository(target_path)
        session = ScanSession(id=str(uuid4()), target_path=target_path, status=SessionStatus.queued, model_authorized=model_authorized)
        self.sessions[session.id] = session
        self._persist(session)
        return session

    async def run(self, session_id: str) -> None:
        session = self.sessions[session_id]
        try:
            from .repository import RepositoryMapper
            analysis = RepositoryMapper(self.sandbox.workspace_root).analyze(session.target_path, True)
            self._event(session, SessionStatus.mapping, f"Mapped {len(analysis.routes)} API routes across {analysis.files_scanned} source files")
            agent_plan: dict[str, object] | None = None
            if session.model_authorized:
                from .agents import AgentProviderError, GeminiAgents, OpenAIAgents
                self._event(session, SessionStatus.testing, "Offensive agent is generating bounded repository-aware test cases")
                try:
                    context = RepositoryMapper(self.sandbox.workspace_root).source_context(session.target_path)
                    provider = GeminiAgents() if __import__("os").environ.get("HYDRABENCH_PROVIDER") == "gemini" else OpenAIAgents()
                    agent_plan = await asyncio.to_thread(provider.generate_repository_test_plan, context, [{"method": route.method, "path": route.path} for route in analysis.routes])
                    self._event(session, SessionStatus.testing, f"Offensive agent generated {len(agent_plan['test_cases'])} bounded test cases")
                except AgentProviderError as error:
                    agent_plan = {"source": "local-fallback", "test_cases": [{"method": route.method, "path": route.path, "name": case, "purpose": case, "expected_status_family": "2xx/4xx", "query": {}, "body": {}} for route in analysis.routes for case in route.test_cases], "coverage_focus": ["route handlers", "input validation", "expected error responses"], "limitations": ["OpenAI test planning was unavailable; using deterministic local cases.", str(error)]}
                    self._event(session, SessionStatus.testing, f"Agent test planning unavailable; generated {len(agent_plan['test_cases'])} local fallback cases")
            test_cases = agent_plan["test_cases"] if agent_plan else [{"method": route.method, "path": route.path, "name": f"{route.method} {route.path}", "expected_status_family": "2xx/4xx", "query": {}, "body": {}} for route in analysis.routes]
            self._event(session, SessionStatus.testing, f"Sandbox runner is executing {len(test_cases)} planned test cases")
            def on_case_result(case_result):
                self._event(session, SessionStatus.testing, f"{case_result.outcome}: {case_result.name} ({case_result.method} {case_result.path} → {case_result.http_status or 'no response'})")
            result = await asyncio.to_thread(self.sandbox.run_repository_validation, session.target_path, True, test_cases, on_case_result)
            detected = [item for item in result.endpoint_results if item.outcome == "VULNERABILITY_DETECTED"]
            unreachable = [item for item in result.endpoint_results if item.outcome == "UNREACHABLE"]
            expectation_failed = [item for item in result.endpoint_results if item.outcome == "EXPECTATION_FAILED"]
            non_passing = [item for item in result.endpoint_results if item.outcome != "PASSED"]
            self._event(session, SessionStatus.analyzing, f"Critic classified {len(detected)} server failures, {len(unreachable)} unreachable routes, and {len(expectation_failed)} expectation mismatches")
            finding = non_passing[0] if non_passing else None
            vector = "Server-side error during bounded route validation" if detected else ("Route did not meet its planned response contract" if expectation_failed else ("Route unreachable during bounded validation" if unreachable else "All planned route validations passed"))
            cause = "The route returned a 5xx response inside the isolated container." if detected else ("The response status did not match the test case's expected status family." if expectation_failed else ("The route could not be reached from the isolated container." if unreachable else "All planned test cases met their expected response status."))
            remediation: dict[str, object] = {}
            failed_case_details = [{**item.model_dump(), "reason": "The endpoint returned a 5xx response inside the isolated Docker container." if item.outcome == "VULNERABILITY_DETECTED" else ("The endpoint could not be reached from inside the isolated Docker container." if item.outcome == "UNREACHABLE" else f"Expected {item.expected_status_family or 'the planned response family'}, but received {item.http_status or 'no response'}." )} for item in non_passing]
            if finding and session.model_authorized:
                self._event(session, SessionStatus.patching, "Defensive agent is analyzing failed cases and relevant repository source")
                failed_cases = [item.model_dump() for item in non_passing]
                try:
                    from .agents import AgentProviderError, GeminiAgents, OpenAIAgents
                    context = RepositoryMapper(self.sandbox.workspace_root).source_context(session.target_path)
                    provider = GeminiAgents() if __import__("os").environ.get("HYDRABENCH_PROVIDER") == "gemini" else OpenAIAgents()
                    remediation = await asyncio.to_thread(provider.generate_remediation, context, failed_cases)
                    patch_diff = str(remediation["patch_diff"])
                    cause = str(remediation["root_cause"])
                    self._event(session, SessionStatus.patching, f"Defensive agent prepared a reviewable proposal for {', '.join(remediation['affected_files']) or 'the affected route'}; no files were modified")
                except AgentProviderError as error:
                    patch_diff = "# No automatic change was made.\n# Review the failed route, its validation, and its error handler using the recorded Docker evidence."
                    remediation = {"verification": ["Rerun the same bounded Docker case after a manual fix."], "limitations": [str(error)]}
                    self._event(session, SessionStatus.patching, "Defensive agent could not generate a source-aware patch; manual review is required")
            elif finding:
                patch_diff = "# No automatic change was made because external model remediation was not authorized.\n# Review the failed route, its validation, and its error handler using the recorded Docker evidence."
                remediation = {"verification": ["Rerun the same bounded Docker case after a manual fix."], "affected_files": []}
                self._event(session, SessionStatus.patching, "A failing case was found, but source-aware model remediation was not authorized")
            else:
                patch_diff = "# No remediation is needed.\n# All bounded Docker cases completed without a 5xx response or unreachable route."
                remediation = {"verification": ["All planned cases passed in the isolated container."], "affected_files": []}
                self._event(session, SessionStatus.patching, "Defensive agent found no failing cases; no code change is proposed")
            remediation["failed_cases"] = failed_case_details
            self._event(session, SessionStatus.verifying, "Container was removed after validation; results were recorded")
            incident = Incident(id="HB-LOCAL-001", severity="HIGH" if detected else ("MEDIUM" if finding else "LOW"), vector=vector, endpoint=finding.path if finding else "All discovered routes", root_cause=cause, status="PROPOSED" if finding else "VERIFIED", patch_diff=patch_diff)
            session.incident = incident
            passed = sum(item.outcome == "PASSED" for item in result.endpoint_results)
            session.report = {"session_metadata": {"target_repository": session.target_path, "timestamp": _now(), "execution": "local-docker", "model_planning": session.model_authorized}, "metrics": {"total_vectors_tested": len(result.endpoint_results), "passed": passed, "compromised": len(non_passing), "auto_patched": 0}, "incidents": [{**incident.model_dump(), "verification": "Bounded route validations completed inside a disposable no-network container."}], "endpoint_results": [item.model_dump() for item in result.endpoint_results], "sandbox_logs": result.logs, "agent_test_plan": agent_plan, "remediation": remediation}
            self._event(session, SessionStatus.resolved, "Pipeline completed; remediation awaits explicit review")
        except (ValueError, Exception) as error:
            self._event(session, SessionStatus.failed, str(error))

    def get(self, session_id: str) -> ScanSession:
        return self.sessions[session_id]

    def latest(self) -> ScanSession:
        if self.sessions:
            return next(reversed(self.sessions.values()))
        if self.session_snapshot.is_file():
            return ScanSession.model_validate_json(self.session_snapshot.read_text(encoding="utf-8"))
        raise KeyError("No sessions")

    def clear_latest(self) -> None:
        """Clear dashboard state before a newly uploaded repository is assessed."""
        self.sessions.clear()
        self.session_snapshot.unlink(missing_ok=True)

    def _event(self, session: ScanSession, status: SessionStatus, message: str) -> None:
        session.status = status
        session.events.append(Event(type="lifecycle", message=message, status=status, timestamp=_now()))
        self._persist(session)

    def _persist(self, session: ScanSession) -> None:
        self.session_snapshot.parent.mkdir(parents=True, exist_ok=True)
        self.session_snapshot.write_text(session.model_dump_json(), encoding="utf-8")

def _now() -> str:
    return datetime.now(UTC).isoformat()
