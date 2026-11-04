import React from 'react';
import { Badge } from '../ui.jsx';

const MILESTONES = [
  ['M1', 'Transport', 'A scripted SDK client sends echo, deliberate failure and echo calls through the stdio proxy. This checks request/response handling.', 'MCP mediation demo'],
  ['M2', 'History representations', 'Prewritten histories are replayed through B0 (current call), B1 (conservative unordered prior facts), B2-R (ordered reference) and B2-S (incremental state). An independent fixture oracle is separate from their findings. B2 agreement checks implementation consistency. No live tools run.', 'Explained here; replay CLI only'],
  ['M3', 'Durable audit', 'The live proxy commits proposal, decision and dispatch records before forwarding a call, then records its outcome in SQLite. This milestone does not sign the evidence.', 'Explained here; standalone CLI only'],
  ['M4', 'Signed evidence & inspection', 'A completed non-release sequence is hash-chained and closed with an ECDSA P-256 signature. Offline inspection checks structure, integrity, signer, context, completeness and reproduced findings. It does not accept a fresh submission.', 'Signed evidence demo'],
  ['M5', 'Complete-run acceptance', 'The assessor registers the run, inventory, configuration and signer before execution. The acceptance registry checks the complete submission and records acceptance durably; duplicate submissions are checked separately from repeatable inspection.', 'Acceptance layer used by M6.4; full M5 campaign is CLI only'],
  ['M6', 'Live scoped permissions', 'A trusted host grants, revokes and consumes one-use permissions for an exact task, source and destination. Client tool requests pass through the real permission gate. M6.4 also exports, inspects and submits that run’s evidence.', 'Live authorization & acceptance demo'],
];

export default function Walkthrough() {
  return <section className="site-walkthrough" id="walkthrough">
    <details className="walkthrough-details"><summary>Site walkthrough · M1–M6 explained</summary>
    <div className="section-title"><div><span className="eyebrow">START HERE</span><h2>A walkthrough of this workspace</h2></div><Badge>SITE GUIDE</Badge></div>
    <ol className="walkthrough-steps">
      <li><strong>Choose a demonstration.</strong> Start with Live authorization & acceptance for the complete permission and evidence flow, or MCP mediation for transport only.</li>
      <li><strong>Inspect the preset inputs.</strong> The payloads and host-control steps are read-only. The browser selects a fixed scenario; it cannot issue grants or arbitrary tool calls.</li>
      <li><strong>Click Run demonstration.</strong> The progress panel shows adapter observations. Actual internal results arrive with the completed report.</li>
      <li><strong>Follow Step-by-step workflow.</strong> Each call’s input, returned content and recorded controller decision appear together. Host grants and revocations link to their committed audit records.</li>
      <li><strong>Compare results across tabs.</strong> Tool outputs show responses; Permissions shows actual dispatch; Detectors shows shadow findings; Evidence separates inspection from acceptance.</li>
      <li><strong>Inspect supporting data.</strong> Execution observations shows local host/server witnesses separately from signed audit. Raw JSON exposes the returned report. Clear result resets the view without replaying tools.</li>
    </ol>
    <details className="milestone-guide"><summary>What M1–M6 demonstrate, and where to find them</summary>
      <p className="subtle">Milestones are different capabilities, not six stages of one uninterrupted conversation. This site launches M1, M4 and a fresh M6.4 scenario. M2/M3 and the full M5 campaign have no standalone UI launch.</p>
      <div className="audit-scroll"><table><thead><tr><th>Milestone</th><th>What it shows</th><th>Availability in this site</th></tr></thead><tbody>{MILESTONES.map(([id, title, description, availability]) => <tr key={id}><td><Badge>{id}</Badge><h3>{title}</h3></td><td>{description}</td><td>{availability}</td></tr>)}</tbody></table></div>
    </details>
    </details>
  </section>;
}
