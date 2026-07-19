import { useEffect, useState } from "react";

type FailedCase = { name: string; method: string; path: string; http_status?: number; outcome: string; expected_status_family?: string; reason: string };
type Remediation = { failed_cases?: FailedCase[] };

export function DiffViewer({ diff, status }: { diff?: string; status: string }) {
  const [remediation, setRemediation] = useState<Remediation>();
  useEffect(() => { fetch("http://localhost:8000/sessions/latest").then(async (response) => { if (response.ok) setRemediation((await response.json()).report?.remediation); }).catch(() => undefined); }, [status]);
  const lines = (diff ?? "A patch proposal will appear here after the Critic and Defensive agent handoff.").split("\n");
  const noChangeNeeded = diff?.includes("No remediation is needed") ?? false;
  const failedCases = remediation?.failed_cases ?? [];
  return <section className="panel diff"><div className="section-heading"><div><p className="kicker">DEFENSIVE AGENT</p><h2>Remediation proposal</h2></div><span className="diff__file">evidence-based</span></div>{failedCases.length ? <div className="remediation-evidence"><strong>Non-passing test evidence</strong>{failedCases.map((test) => <article key={`${test.name}-${test.path}`}><code>{test.method} {test.path}</code><b>{test.name} · expected {test.expected_status_family ?? "n/a"} · received {test.http_status ?? "no response"}</b><p>{test.reason}</p></article>)}</div> : <p className="remediation-clean">All planned test cases passed their expected response checks.</p>}<div className="diff__body">{lines.map((line, index) => <code className={line.startsWith("+") ? "add" : line.startsWith("-") ? "remove" : ""} key={`${index}-${line}`}>{line || " "}</code>)}</div><footer><span>Patch status</span><strong>{noChangeNeeded ? "No change needed" : status === "resolved" ? "Awaiting approval" : "Not generated"}</strong></footer></section>;
}
