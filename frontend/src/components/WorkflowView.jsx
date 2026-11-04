import React from 'react';
import { Badge, Empty, Json } from '../ui.jsx';
import { isActive, observedStep, outputs, outputState, resultText } from '../model.js';

export function WorkflowView({ scenario, run }) {
  if (!scenario?.workflow) return <Empty title="Choose a demonstration">Select a scenario to preview its inputs and the steps it will execute.</Empty>;
  const finished = Boolean(run?.result);
  return <div className="workflow-view">
    <div className="section-note"><strong>{finished ? 'Observed results' : 'Workflow preview'} · {scenario.title}</strong><p>{finished ? 'Each result below comes from the completed run. Expand a step for its recorded data.' : 'This preview shows preset inputs and workflow structure only. Outputs appear after execution.'}</p></div>
    <ol className="workflow-list">{scenario.workflow.map((step, index) => {
      const observed = observedStep(step, run);
      const input = observed?.output?.arguments ?? (step.kind === 'tool' ? step.arguments : { scope: step.scope, ...(step.grant_id ? { grant_id: step.grant_id } : {}) });
      return <li className={`workflow-step ${observed?.state.tone || ''}`} key={step.id}>
        <span className="workflow-number">{String(index + 1).padStart(2, '0')}</span>
        <article>
          <div className="workflow-heading"><div><span className="eyebrow">{step.kind === 'tool' ? 'TOOL CALL' : 'TRUSTED HOST CONTROL'}</span><h3>{step.title}</h3></div><Badge tone={observed?.state.tone}>{observed?.state.label || (isActive(run) ? 'AWAITING RESULTS' : run ? 'NOT OBSERVED' : 'PLANNED')}</Badge></div>
          <p>{step.why}</p>
          <div className="step-io">
            <div><span className="field-label">{observed?.output ? 'Sent input' : 'Preset input'} · {step.tool || step.kind}</span><Json value={input}/></div>
            <div><span className="field-label">Recorded output</span>
              {observed?.output ? <pre className="tool-result">{resultText(observed.output)}</pre> : observed?.event ? <p className="control-result">Permission change committed · audit record #{observed.event.seq}</p> : <p className="pending-result">{isActive(run) ? 'Waiting for the run report.' : run ? 'No recorded result is available for this step.' : 'Run the demonstration to see its actual output.'}</p>}
              {observed?.decision && <p className="decision-explanation"><strong>Controller: {observed.decision.body.dispatch_decision}</strong> · {observed.decision.body.reason}</p>}
            </div>
          </div>
          {observed && <details><summary>Inspect recorded {step.kind === 'tool' ? 'response and decision' : 'host control'}</summary><Json value={observed.event || { response: observed.output.response, decision: observed.decision || null }}/></details>}
        </article>
      </li>;
    })}</ol>
    {finished && <div className="takeaway"><strong>What this demonstrates</strong><p>{scenario.takeaway}</p><p>A completed run is not a claim that every call was allowed. Policy denials and tool failures remain visible above.</p></div>}
  </div>;
}

export function RunOverview({ run, scenario, onInspect }) {
  if (!run?.result) return null;
  const calls = outputs(run);
  const count = label => calls.filter(output => outputState(output).label === label).length;
  const verification = run.result.evidence?.verification;
  const acceptance = run.result.evidence?.acceptance;
  return <div className="run-overview">
    <div className="overview-title"><div><span className="eyebrow">COMPLETED RUN</span><h2>{scenario?.title || run.scenario_id}</h2></div><button className="text-button" onClick={onInspect}>Inspect step by step →</button></div>
    <div className="outcome-counts"><div><strong>{count('RETURNED')}</strong><span>Returned normally</span></div><div><strong>{count('POLICY DENIED')}</strong><span>Denied before dispatch</span></div><div><strong>{count('TOOL ERROR')}</strong><span>Deliberate tool errors</span></div><div><strong>{verification ? (verification.inspection_passed ? 'Passed' : 'Not passed') : 'Not produced'}</strong><span>Evidence inspection</span></div></div>
    <p>{acceptance?.status === 'ACCEPTED' ? 'The evidence passed the registered-run submission checks. Acceptance does not certify benign behavior.' : acceptance ? 'This scenario inspects evidence without accepting a fresh submission.' : 'This transport scenario produces tool responses; it does not produce signed evidence.'}</p>
  </div>;
}

export function SystemFlow() {
  const nodes = [
    ['01', 'Input', 'A tool request or a trusted host permission change.'],
    ['02', 'Context & decision', 'ChainGuard checks prior reads, grants and revocations.'],
    ['03', 'Tool & audit', 'The host permits or denies dispatch and records the outcome.'],
    ['04', 'Evidence', 'Completed records are signed, inspected and, where supported, accepted.'],
  ];
  return <section className="system-flow" aria-label="How ChainGuard works">
    <div className="section-title"><h2>From a tool request to inspectable evidence</h2><span>Four stages. Separate responsibilities.</span></div>
    <div className="flow-nodes">{nodes.map(([number, title, description]) => <article key={number}><span>{number}</span><h3>{title}</h3><p>{description}</p></article>)}</div>
    <p className="flow-footnote">M1 covers transport only. M4 adds audit and signatures. M6 adds scoped permissions. Detector findings, actual dispatch and evidence acceptance are different results.</p>
  </section>;
}
