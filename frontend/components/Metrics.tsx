export function Metrics({ session }: { session?: any }) {
  const metrics = session?.report?.metrics ?? { total_vectors_tested: 0, passed: 0, compromised: 0, auto_patched: 0 };
  const cards = [["Vectors tested", metrics.total_vectors_tested, "teal"], ["Healthy", metrics.passed, "blue"], ["Incidents", metrics.compromised, "orange"], ["Auto-patched", metrics.auto_patched, "violet"]];
  return <section className="metrics">{cards.map(([label, value, tone]) => <article className={`metric metric--${tone}`} key={String(label)}><span>{label}</span><strong>{value}</strong><i /></article>)}</section>;
}
