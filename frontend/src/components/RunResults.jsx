import React from 'react';
import { Badge, Empty, Json } from '../ui.jsx';
import { DETECTORS, auditRecords, decisions, findings, outputState, outputs, time } from '../model.js';

const VERIFICATION_HELP = {
  schema_lifecycle: 'Checks record format, identities, ordering and the request/response lifecycle.',
  package_schema: 'Checks the supported package version and canonical evidence format.',
  commitment_integrity: 'Checks the event hashes, chain links, record count and signed final commitment.',
  trusted_signature: 'Checks the closure signature using the assessor’s pinned public key.',
  expected_binding: 'Checks the run, task, challenge and configuration against independently registered context.',
  inventory_completeness: 'Checks that the required signed sessions are present in this submission.',
  lifecycle_semantics: 'Checks the recorded grant, revocation and one-use permission lifecycle.',
  finding_reproduction: 'Runs the approved evaluators on recorded facts and compares their findings. This does not prove that those facts are true.',
};

export default function RunResults({ tab, run, scenario, busy }) {
  const evidence = run?.result?.evidence;
  const records = auditRecords(run);

  if (tab === 'observations') {
    const observations = run?.result?.report?.observations;
    if (!observations) return <Empty icon="pulse" title="Execution observations are available in M6">Run the permission-lifecycle demo to inspect host admissions, committed intents, tool arrivals and sink observations.</Empty>;
    return <><div className="section-note"><strong>Observed execution, separate from signed audit</strong><p>{observations.basis}</p><p>No external assessor sink is configured. The sink observations below are emitted by the controlled local tool server.</p></div>
      {['host', 'child'].map(source => <section key={source}><div className="audit-heading"><h3>{source === 'host' ? 'Host observations' : 'Controlled-server observations'}</h3><Badge>{observations[source].length} RECORDS</Badge></div><div className="audit-scroll"><table><thead><tr><th>Source order</th><th>Phase</th><th>Request / control</th><th>Details</th></tr></thead><tbody>{observations[source].map((event, index) => <tr key={index}><td>{event.sequence ?? index + 1}</td><td>{event.phase.replaceAll('_', ' ')}</td><td>{event.request_id ?? event.kind ?? '—'}</td><td><details><summary>Inspect observation</summary><Json value={event}/></details></td></tr>)}</tbody></table></div></section>)}
    </>;
  }

  if (tab === 'outputs') {
    const rows = outputs(run);
    if (!rows.length) return <Empty icon="code" title={busy ? 'Waiting for the runtime' : 'Real results, ready to inspect'}>Run a demonstration to see actual responses, policy denials and tool errors.</Empty>;
    return <div className="output-list">{rows.map((output, index) => {
      const state = outputState(output);
      return <article className="output-card" key={`${typeof output.request_id}-${output.request_id ?? index}`}>
        <div className="output-title"><span className="output-number">{String(index + 1).padStart(2, '0')}</span><code>{output.tool}</code><Badge tone={state.tone}>{state.label}</Badge>{output.request_id != null && <small>Request {output.request_id}</small>}</div>
        {output.arguments && <details><summary>Input arguments</summary><Json value={output.arguments}/></details>}
        {output.response?.error ? <div className="response-error"><p>{output.response.error.message}</p><small>Code: {output.response.error.code} · {state.label === 'POLICY DENIED' ? 'The controller refused dispatch.' : 'Protocol request failed.'}</small></div> : <pre className="tool-result">{output.response?.result?.content?.map(c => c.text ?? JSON.stringify(c)).join('\n') ?? 'No response recorded.'}</pre>}
      </article>;
    })}</div>;
  }

  if (tab === 'authorization') {
    const rows = decisions(run);
    if (!rows.length) return <Empty icon="shield" title="Inspect actual dispatch decisions">Run M6.4 to see scoped permission checks, one-use grants and revocation. M1 has no policy evaluation.</Empty>;
    const controls = records.map(({ event }) => event).filter(event => ['GRANT', 'REVOKE_SCOPE'].includes(event.event_type));
    return <>
      <div className="section-note">These are the host controller's recorded decisions. Detector findings are separate shadow evaluations; a detector warning does not imply that the host denied the call.</div>
      <div className="audit-scroll"><table><thead><tr><th>Tool / request</th><th>Dispatch</th><th>Authorization</th><th>Reason & evidence</th></tr></thead><tbody>{rows.map(event => { const proposal = records.map(r => r.event).find(item => item.event_type === 'CALL_PROPOSAL' && item.call_id === event.call_id); return <tr key={event.event_id}>
        <td><code>{proposal?.body.tool || 'Unknown tool'}</code><p className="subtle">{proposal?.body.request_id ?? 'No request ID'} · record #{event.seq}</p></td><td><Badge tone={event.body.dispatch_decision === 'DENY' ? 'amber' : 'green'}>{event.body.dispatch_decision}</Badge></td><td>{event.body.authorization_assessment}</td>
        <td><p>{event.body.reason}</p><details><summary>Inspect decision</summary><Json value={event}/></details></td>
      </tr>; })}</tbody></table></div>
      {controls.length > 0 && <><div className="audit-heading"><h3>Committed host controls</h3><Badge>{controls.length} EVENTS</Badge></div>{controls.map(event => <details key={event.event_id}><summary>#{event.seq} · {event.event_type}</summary><Json value={event}/></details>)}</>}
      <Acceptance evidence={evidence} report={run?.result?.report}/>
    </>;
  }

  if (tab === 'detectors') return <>
    <div className="section-note">{scenario?.detector_note || 'Findings are shown only when the selected run contains recorded detector evidence.'}</div>
    <div className="detector-grid">{DETECTORS.map(id => {
      const rows = findings(run, id);
      return <article className="detector-card" key={id}>
        <div><h3>{id}</h3><span>{({ B0: 'Current event', B1: 'Unordered prefix', 'B2-R': 'Ordered reference', 'B2-S': 'Incremental state' })[id]}</span></div>
        {rows.length ? rows.map(event => <details key={event.event_id}><summary><Badge tone={event.body.behavioral_verdict === 'ALLOW' ? 'neutral' : 'amber'}>{event.body.behavioral_verdict}</Badge><span>#{event.seq} · {event.body.rule_id}</span></summary><p>{event.body.explanation}</p><p>Authorization: {event.body.authorization_assessment}</p><Json value={event.body}/></details>) : <p>No findings available. Run M4 or M6.4 to inspect recorded findings.</p>}
      </article>;
    })}</div>
  </>;

  if (tab === 'audit') {
    if (!evidence) return <Empty icon="shield" title="Evidence stays distinct from behavior">Run M4 or M6.4 for audit records, a signed closure and offline inspection. M1 does not produce signed evidence.</Empty>;
    return <>
      <div className="verification-grid">{Object.entries(evidence.verification.dimensions).map(([key, value]) => <article className="verification-card" key={key}><div><span>{key.replaceAll('_', ' ')}</span><Badge tone={value.status === 'PASS' ? 'green' : 'amber'}>{value.status}</Badge></div><p>{VERIFICATION_HELP[key] || value.reason}</p><details><summary>Verifier details</summary><Json value={value}/></details></article>)}</div>
      <Acceptance evidence={evidence} report={run?.result?.report}/>
      <details><summary>Full inspection report, including session checks</summary><Json value={evidence.verification}/></details>
      <details><summary>Signed closure & final chain head</summary><Json value={evidence.package.commitment}/></details>
      <div className="audit-heading"><h3>Recorded audit timeline</h3><Badge>{records.length} RECORDS</Badge></div>
      <p className="subtle">Persisted runtime timestamps and sequence numbers. Retrieved after completion.</p>
      <div className="audit-scroll"><table><thead><tr><th>Seq</th><th>Observed time</th><th>Event</th><th>Record details</th></tr></thead><tbody>{records.map(({ event }) => <tr key={event.event_id}><td className="mono">{event.seq}</td><td className="mono">{time(event.observed_at_utc)}</td><td>{event.event_type}</td><td><details><summary>Inspect record</summary><Json value={event}/></details></td></tr>)}</tbody></table></div>
    </>;
  }

  return run ? <Json value={run}/> : <Empty icon="code" title="No run selected">The actual runtime report and adapter metadata appear here after a run is created.</Empty>;
}

function Acceptance({ evidence, report }) {
  if (!evidence) return null;
  const acceptance = evidence.acceptance;
  const duplicate = report?.duplicate_submission;
  return <div className="acceptance-panel">
    <div className="audit-heading"><h3>Complete-run acceptance</h3><Badge tone={acceptance.status === 'ACCEPTED' ? 'green' : ''}>{acceptance.status}</Badge></div>
    <p>{acceptance.reason}{acceptance.registry_durability && ` · Registry: ${acceptance.registry_durability}`}</p>
    {duplicate && <p>Duplicate submission after registry reopen: <strong>{duplicate.status}</strong> · {duplicate.reason}</p>}
    <p>Inspection and acceptance are separate operations. Signatures authenticate commitments; they do not prove observation truth or safe behavior.</p>
    {report?.limits?.map(limit => <p key={limit}>{limit}</p>)}
    <details><summary>Inspect acceptance result</summary><Json value={acceptance}/></details>
  </div>;
}
