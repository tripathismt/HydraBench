from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI
from google import genai

from .templates import CRITIC_POLICY, DEFENSIVE_POLICY, OFFENSIVE_POLICY

load_dotenv(Path(__file__).resolve().parents[1] / ".env")


class AgentProviderError(RuntimeError):
    pass


def repository_test_schema() -> dict[str, Any]:
    return {
        "type": "object", "additionalProperties": False,
        "properties": {
            "test_cases": {"type": "array", "items": {"type": "object", "additionalProperties": False, "properties": {"method": {"type": "string"}, "path": {"type": "string"}, "name": {"type": "string"}, "purpose": {"type": "string"}, "expected_status_family": {"type": "string"}, "query": {"type": "object", "additionalProperties": {"type": "string"}}, "headers": {"type": "object", "additionalProperties": {"type": "string"}}, "body": {"type": "object", "additionalProperties": True}, "raw_body": {"type": "string"}}, "required": ["method", "path", "name", "purpose", "expected_status_family", "query", "headers", "body", "raw_body"]}},
            "coverage_focus": {"type": "array", "items": {"type": "string"}}, "limitations": {"type": "array", "items": {"type": "string"}}
        }, "required": ["test_cases", "coverage_focus", "limitations"]
    }


def remediation_schema() -> dict[str, Any]:
    return {
        "type": "object", "additionalProperties": False,
        "properties": {
            "root_cause": {"type": "string"},
            "affected_files": {"type": "array", "items": {"type": "string"}},
            "patch_diff": {"type": "string"},
            "verification": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["root_cause", "affected_files", "patch_diff", "verification"],
    }


class GeminiAgents:
    def __init__(self) -> None:
        key = os.getenv("GEMINI_API_KEY")
        if not key:
            raise AgentProviderError("GEMINI_API_KEY is not configured.")
        self.client = genai.Client(api_key=key)
        self.model = os.getenv("HYDRABENCH_GEMINI_MODEL", "gemini-3.5-flash")

    def generate_repository_test_plan(self, source_context: str, routes: list[dict[str, str]]) -> dict[str, Any]:
        prompt = """You are HydraBench's authorized repository test planner. Create a high-value, bounded HTTP API test plan for the supplied local repository. The plan will execute only inside one disposable, no-network Docker container against this repository. Use the discovered routes and source context as the authority; do not invent undocumented routes except for one safe 404/not-found check.

Coverage requirements:
1. Cover every discovered route at least once with its safest meaningful request.
2. First trace each route through its mounted router, middleware, controller/handler, validator, service call, and error handler. Use that control flow to name the branch each test targets. Include local helper functions when their behavior is reachable from an HTTP route.
3. For every input-bearing route, select distinct safe cases across: missing field, null-like/empty/whitespace value, invalid type or format, minimum and maximum boundary, just-outside boundary, unexpected-but-benign field, duplicate/idempotent request where safe, and a valid representative input when it does not require credentials or outbound access.
4. Exercise protocol and parser branches where source supports them: wrong but harmless Content-Type, malformed JSON using raw_body, absent body, unsupported method, unknown route (one case), and documented error middleware/error response shape. Use raw_body only for small parser-validation payloads; otherwise leave it as an empty string.
5. Test branching and state safely: cache miss/hit statistics, safe reset/clear behavior, repeated read behavior, and ordering dependencies only when the state is disposable and reversible in the Docker container. Put all state-changing cases after reads and label them clearly.
6. Account for external dependencies and configuration gates. Do not make provider calls, credential guesses, or network-dependent assertions. Instead cover deterministic local validation, disabled/unconfigured branches, and documented graceful error paths. An expected configuration error may use expected_status_family 5xx only when source proves it is intentional.
7. Prefer a compact but deep plan: 2–8 cases per route, up to 60 total. Avoid duplicate cases and explain the unique branch or condition each case covers.

Safety limits:
- No exploit payloads, security-control bypasses, credential tests, fuzzing, high-volume/concurrent requests, large payloads, filesystem/process probes, external targets, or destructive operations outside safe disposable-container state.
- Do not claim line coverage or test behavior that is not evidenced by the supplied source.
- Every case must be deterministic, quick, and executable by a simple HTTP client.

For each case, provide a concise descriptive name, why it covers a distinct branch, the expected HTTP status family, string-only query values, safe string headers, a small JSON body when needed, and raw_body (empty string unless deliberately testing JSON parsing). Use only GET, POST, PUT, PATCH, or DELETE methods.

Discovered routes:
""" + json.dumps(routes) + "\n\nRepository source context (secrets excluded):\n" + source_context
        try:
            response = self.client.models.generate_content(model=self.model, contents=prompt, config={"response_mime_type": "application/json", "response_json_schema": repository_test_schema()})
            return json.loads(response.text)
        except Exception as error:
            raise AgentProviderError(f"Gemini repository_test_plan failed: {error}") from error

    def generate_remediation(self, source_context: str, failed_cases: list[dict[str, Any]]) -> dict[str, Any]:
        prompt = """You are HydraBench's defensive remediation analyst for an explicitly authorized local repository. Analyze only the supplied repository source and bounded Docker test failures. Provide a minimal, reviewable unified diff only when the evidence identifies a concrete code defect. Do not modify files, add dependencies, include secrets, introduce network calls, weaken validation, or make speculative changes. Keep the patch limited to affected files and explain how to verify it in the same isolated test environment.\n\nFailed test evidence:\n""" + json.dumps(failed_cases) + "\n\nRepository source context (secrets excluded):\n" + source_context
        try:
            response = self.client.models.generate_content(model=self.model, contents=prompt, config={"response_mime_type": "application/json", "response_json_schema": remediation_schema()})
            return json.loads(response.text)
        except Exception as error:
            raise AgentProviderError(f"Gemini remediation failed: {error}") from error


class OpenAIAgents:
    """A small, auditable provider boundary for the three-agent handoff."""

    def __init__(self) -> None:
        key = os.getenv("OPENAI_API_KEY")
        if not key:
            raise AgentProviderError("OPENAI_API_KEY is not configured.")
        self.client = OpenAI(api_key=key)
        self.model = os.getenv("HYDRABENCH_MODEL", "gpt-5.6")

    def plan_test(self, source: str) -> dict[str, Any]:
        return self._structured(
            OFFENSIVE_POLICY,
            f"Target source (local mock only):\n{source}\n\nPlan one request-body validation case.",
            "test_plan",
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "endpoint": {"type": "string"},
                    "method": {"type": "string", "enum": ["POST"]},
                    "case_name": {"type": "string"},
                    "request_body": {"type": "object", "additionalProperties": True},
                    "expected_outcome": {"type": "string"},
                },
                "required": ["endpoint", "method", "case_name", "request_body", "expected_outcome"],
            },
        )

    def analyze_failure(self, source: str, test_plan: dict[str, Any]) -> dict[str, Any]:
        simulated_log = "TypeError: Cannot read properties of undefined (reading 'cartId') at server.js:6"
        return self._structured(
            CRITIC_POLICY,
            f"Source:\n{source}\n\nTest plan:\n{json.dumps(test_plan)}\n\nObserved local mock log:\n{simulated_log}",
            "incident_analysis",
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "root_file": {"type": "string"},
                    "line": {"type": "integer"},
                    "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                    "vector": {"type": "string"},
                    "root_cause": {"type": "string"},
                },
                "required": ["root_file", "line", "severity", "vector", "root_cause"],
            },
        )

    def propose_patch(self, source: str, analysis: dict[str, Any]) -> dict[str, Any]:
        return self._structured(
            DEFENSIVE_POLICY,
            f"Source:\n{source}\n\nCritic analysis:\n{json.dumps(analysis)}",
            "patch_proposal",
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "patch_diff": {"type": "string"},
                    "verification": {"type": "string"},
                },
                "required": ["patch_diff", "verification"],
            },
        )

    def generate_remediation(self, source_context: str, failed_cases: list[dict[str, Any]]) -> dict[str, Any]:
        return self._structured(
            """You are HydraBench's defensive remediation analyst. Analyze only the supplied authorized local repository source and bounded Docker failures. Propose a minimal unified diff only for an evidenced concrete code defect. Do not modify files, add dependencies, include secrets, introduce network calls, weaken validation, or make speculative changes.""",
            f"Failed test evidence:\n{json.dumps(failed_cases)}\n\nRepository source context (secrets excluded):\n{source_context}",
            "repository_remediation",
            remediation_schema(),
        )

    def generate_repository_test_plan(self, source_context: str, routes: list[dict[str, str]]) -> dict[str, Any]:
        return self._structured(
            """You are HydraBench's authorized repository test planner. Generate safe, bounded cases that trace discovered routes through middleware, validators, handlers, local helpers, service branches, and error handling. Cover meaningful valid, missing, empty, boundary, invalid-format, parser/content-type, safe state, and documented unconfigured dependency branches. Do not generate exploit code, fuzzing, credential tests, external calls, high-volume tests, or destructive actions outside safe disposable-container state. Return no more than 60 distinct cases.""",
            f"Discovered routes:\n{json.dumps(routes)}\n\nRepository source context (secrets excluded):\n{source_context}",
            "repository_test_plan",
            repository_test_schema(),
        )

    def _structured(self, instructions: str, input_text: str, name: str, schema: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self.client.responses.create(
                model=self.model,
                instructions=instructions,
                input=input_text,
                text={"format": {"type": "json_schema", "name": name, "strict": True, "schema": schema}},
            )
            return json.loads(response.output_text)
        except Exception as error:
            raise AgentProviderError(f"{name} failed: {error}") from error
