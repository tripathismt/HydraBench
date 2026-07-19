import { useEffect, useState } from "react";

type TestResult = { name: string; method: string; path: string; http_status?: number; outcome: string };
type PipelineSession = { status: string; target_path?: string; report?: { agent_test_plan?: { test_cases?: unknown[] }; endpoint_results?: TestResult[] } };

const stages = [["Queued", "Run authorization recorded"], ["Mapped", "Repository routes and source files indexed"], ["Testing", "Agent plan executed in Docker"], ["Analyzing", "Responses classified for failures"], ["Patching", "Remediation recommendation prepared"], ["Verifying", "Container removed and evidence recorded"], ["Resolved", "Pipeline report ready for review"]];
const states: Record<string, number> = { queued: 0, mapping: 1, testing: 2, analyzing: 3, patching: 4, verifying: 5, resolved: 6, failed: 5 };

export function AttackTree({ status: statusFromPipeline }: { status: string }) {
  const [session, setSession] = useState<PipelineSession>();
  useEffect(() => { fetch("http://localhost:8000/sessions/latest").then(async (response) => { if (response.ok) setSession(await response.json() as PipelineSession); }).catch(() => undefined); }, [statusFromPipeline]);
  const status = session?.status ?? statusFromPipeline;
  const active = states[status] ?? 0;
  const target = session?.target_path?.split(/[\\/]/).filter(Boolean).pop() ?? "Awaiting repository";
  const tests = session?.report?.endpoint_results ?? [];
  const planned = session?.report?.agent_test_plan?.test_cases?.length ?? 0;
  return <section className="panel attack-tree"><div className="section-heading"><div><p className="kicker">PIPELINE</p><h2>Repository test flow</h2></div><span className={`status-pill status-pill--${status}`}>{status}</span></div><div className="tree-root">AUTHORIZED REPOSITORY<span>{target}</span></div><div className="tree-summary"><span>{planned || tests.length} planned tests</span><span>{tests.length} executed</span><span>{tests.filter((test) => test.outcome === "PASSED").length} passed</span></div><ol className="stages">{stages.map(([stage, detail], index) => <li className={index < active ? "done" : index === active ? "active" : ""} key={stage}><i>{index < active ? "✓" : index + 1}</i><div><strong>{stage}</strong><small>{detail}</small></div></li>)}</ol>{tests.length ? <div className="tree-tests"><strong>Executed test cases</strong>{tests.map((test) => <div className={`tree-test tree-test--${test.outcome.toLowerCase()}`} key={`${test.name}-${test.path}`}><span>{test.outcome === "PASSED" ? "✓" : "!"}</span><code>{test.method} {test.path}</code><small>{test.name} · {test.http_status ?? "no response"}</small></div>)}</div> : <p className="repository__empty">Each Docker test result will appear here as the pipeline runs.</p>}</section>;
}
