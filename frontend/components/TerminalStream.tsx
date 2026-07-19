export type RunEvent = { timestamp: string; message: string; status: string };

export function TerminalStream({ title, events, tone = "agent" }: { title: string; events: RunEvent[]; tone?: "agent" | "system" }) {
  return <section className={`terminal terminal--${tone}`}><div className="terminal__header"><h2>{title}</h2><span className="terminal__lamp" /></div><div className="terminal__body">{events.length === 0 ? <p className="terminal__placeholder">Waiting for an authorized scan…</p> : events.map((event, index) => <p key={`${event.timestamp}-${index}`}><time>{new Date(event.timestamp).toLocaleTimeString()}</time><b>{event.status.toUpperCase()}</b>{event.message}</p>)}</div></section>;
}
