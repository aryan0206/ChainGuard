import React, { useEffect, useState } from 'react';
import { request } from './api.js';
import { isActive, time } from './model.js';
import { Icon, Badge, Empty, Json } from './ui.jsx';
import RunResults from './components/RunResults.jsx';
import { WorkflowView, RunOverview, SystemFlow } from './components/WorkflowView.jsx';
import Walkthrough from './components/Walkthrough.jsx';

const TABS = [['workflow', 'Step-by-step workflow'], ['outputs', 'Tool outputs'], ['detectors', 'Detectors'],
  ['authorization', 'Permissions'], ['audit', 'Evidence'], ['observations', 'Execution observations'], ['raw', 'Raw JSON']];

export default function App() {
  const [health, setHealth] = useState(null);
  const [scenarios, setScenarios] = useState([]);
  const [scenarioId, setScenarioId] = useState('live-authorization');
  const [run, setRun] = useState(null);
  const [runId, setRunId] = useState(() => sessionStorage.getItem('chainguard-run'));
  const [tab, setTab] = useState('workflow');
  const [error, setError] = useState('');
  const [starting, setStarting] = useState(false);

  useEffect(() => {
    let active = true;
    async function refresh() {
      try {
        const [status, catalog] = await Promise.all([request('/health'), request('/scenarios')]);
        if (active) { setHealth(status); setScenarios(catalog.scenarios); }
      } catch { if (active) setHealth(null); }
    }
    refresh();
    const interval = setInterval(refresh, 5000);
    return () => { active = false; clearInterval(interval); };
  }, []);

  useEffect(() => {
    if (!runId) return;
    const controller = new AbortController();
    let timer;
    async function poll() {
      try {
        const current = await request(`/runs/${encodeURIComponent(runId)}`, { signal: controller.signal });
        if (controller.signal.aborted) return;
        setRun(current);
        if (isActive(current)) timer = setTimeout(poll, 1000);
      } catch (err) {
        if (controller.signal.aborted) return;
        if (err.status === 404) {
          sessionStorage.removeItem('chainguard-run'); setRun(null); setRunId(null);
          setError('The previous run expired or the backend restarted. Start a new demonstration.');
          return;
        }
        setError(err.message); timer = setTimeout(poll, 4000);
      }
    }
    poll();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [runId]);

  async function start() {
    setStarting(true); setError('');
    try {
      const created = await request('/runs', { method: 'POST', body: JSON.stringify({ scenario_id: scenarioId }) });
      setRun(created); setRunId(created.run_id); sessionStorage.setItem('chainguard-run', created.run_id); setTab('workflow');
    } catch (err) { setError(err.message); }
    finally { setStarting(false); }
  }
  function reset() { setRun(null); setRunId(null); sessionStorage.removeItem('chainguard-run'); setError(''); }
  function choose(value) { setScenarioId(value); reset(); setTab('workflow'); }
  function inspect(value) { setTab(value); document.getElementById('results')?.scrollIntoView({ behavior: 'smooth', block: 'start' }); }

  const selected = scenarios.find(s => s.id === scenarioId);
  const runScenario = scenarios.find(s => s.id === run?.scenario_id) || selected;
  const busy = starting || isActive(run);
  const connected = health?.runtime_ready;
  const samples = selected?.workflow?.filter(step => step.kind === 'tool').filter((step, index, all) =>
    all.findIndex(other => other.tool === step.tool && JSON.stringify(other.arguments) === JSON.stringify(step.arguments)) === index) || [];

  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="#top"><Icon name="shield" size={28}/>ChainGuard<span>.</span></a>
      <div className="workspace-label"><span className="status-dot online"/> LOCAL DEMO WORKSPACE</div>
      <nav aria-label="Workspace navigation">
        <a className="walkthrough-link" href="#walkthrough"><Icon name="file"/>Site walkthrough</a>
        <button className={tab === 'workflow' ? 'active' : ''} onClick={() => inspect('workflow')}><Icon name="grid"/>Guided workflow</button>
        <button className={tab === 'outputs' ? 'active' : ''} onClick={() => inspect('outputs')}><Icon name="code"/>Inputs & outputs</button>
        <button className={tab === 'authorization' ? 'active' : ''} onClick={() => inspect('authorization')}><Icon name="shield"/>Permissions</button>
        <button className={tab === 'detectors' ? 'active' : ''} onClick={() => inspect('detectors')}><Icon name="pulse"/>Detector comparison</button>
        <button className={tab === 'audit' ? 'active' : ''} onClick={() => inspect('audit')}><Icon name="file"/>Audit & evidence</button>
      </nav>
      <div className="sidebar-explainer"><Icon name="shield"/><strong>Why history matters</strong><p>A tool call can depend on what was read earlier, whether permission was granted, and whether that permission was used or revoked.</p></div>
      <a className="docs-link" href="https://github.com/aryan0206/ChainGuard#readme" target="_blank" rel="noreferrer">Project documentation ↗</a>
      <span className="sidebar-version">Controlled tools · synthetic data</span>
    </aside>

    <div className="main-shell" id="top">
      <header className="topbar"><span>Workspace <span className="slash">/</span> Interactive demonstration</span><div><span className={`status-dot ${connected ? 'online' : ''}`}/>{health ? (connected ? 'Runtime ready' : 'Runtime unavailable') : 'Connecting to backend'}{health?.revision && <code title="Current checkout revision supplied by the local host">{health.revision.slice(0, 7)}</code>}</div></header>
      <main>
        <div className="page-heading"><div><span className="eyebrow">EXPLAINABLE MCP SECURITY</span><h1>Understand every step<br/>of a tool's journey.</h1><p>See what goes in, why a call is allowed or denied, and what the recorded evidence can verify.</p></div><span className="hero-mark"><Icon name="shield" size={66}/></span></div>
        <SystemFlow/>
        <Walkthrough/>
        {!health && <div className="notice">Waiting for the local backend at <code>127.0.0.1:8001</code>. Start both servers using the README commands.</div>}
        {health && !connected && <div className="notice">The API is online, but runtime validation failed. Check the Python environment and restart the backend.</div>}
        {error && <div role="alert" className="error-banner"><span>{error}</span><button aria-label="Dismiss error" onClick={() => setError('')}>×</button></div>}

        <div className="execution-grid">
          <section className="panel setup-panel">
            <div className="panel-heading"><span className="step">1</span><div><h2>Choose a demonstration</h2><p>Preview the inputs before you run.</p></div></div>
            <div className="panel-body">
              <label htmlFor="scenario">Demonstration</label>
              <select id="scenario" value={scenarioId} onChange={event => choose(event.target.value)} disabled={busy || !scenarios.length}>
                {scenarios.length ? scenarios.map(s => <option key={s.id} value={s.id}>{s.title} · {s.milestone}</option>) : <option value="live-authorization">Loading demonstrations…</option>}
              </select>
              <div className="scenario-question"><Badge>{selected?.milestone || 'LOCAL'}</Badge><h3>{selected?.question || 'Waiting for scenario discovery.'}</h3><p>{selected?.description}</p></div>
              <div className="input-heading"><h3>Preset inputs</h3><Badge>READ ONLY</Badge></div>
              <p className="subtle">{selected?.input_note || 'Only the approved demonstration is selected in your browser.'}</p>
              <div className="input-samples">{samples.map(step => <div key={step.id}><code>{step.tool}</code><Json value={step.arguments}/></div>)}</div>
              <div className="run-controls"><button className="primary-button" onClick={start} disabled={!connected || busy || health?.busy}><Icon name="play" size={17}/>{busy ? 'Running demonstration…' : health?.busy ? 'Another demo is running…' : 'Run demonstration'}</button><button className="reset-button" onClick={reset} disabled={busy || !runId}>Clear result</button></div>
              <p className="local-caption">Existing ChainGuard mediation · synthetic local tools</p>
            </div>
          </section>

          <section className="panel progress-panel">
            <div className="panel-heading"><span className="step">2</span><div><h2>Watch execution progress</h2><p>Progress is separate from security findings.</p></div><Badge tone={busy ? 'green' : ''}>{run?.status?.replace('_', ' ').toUpperCase() || 'READY'}</Badge></div>
            {!run ? <Empty title="Ready when you are">Run the selected demonstration. Actual outputs and audit records will appear after it finishes.</Empty> : <div className="timeline" aria-live="polite">
              {run.events.map(event => <div className="timeline-row" key={event.sequence}><span className="timeline-dot"/><div><strong>{({ run_accepted: 'Run accepted', demo_process_started: 'ChainGuard workflow started', demo_result_received: 'Actual results received', run_finalized: 'Run finished' })[event.event] || event.event.replaceAll('_', ' ')}</strong><small>Adapter observation · #{event.sequence}</small></div><time>{time(event.timestamp)}</time></div>)}
              <p className="progress-explanation">Internal tool steps are shown once the report is returned. The UI does not infer live permission changes.</p>
              {run.error && <p className="inline-error">{run.error.message}</p>}
              <div className="run-id">RUN <code>{run.run_id}</code></div>
            </div>}
            <div className="progress-legend"><div><span className="legend-dot green"/><p><strong>Returned</strong>Tool executed normally.</p></div><div><span className="legend-dot amber"/><p><strong>Denied</strong>Controller refused dispatch.</p></div><div><span className="legend-dot coral"/><p><strong>Tool error</strong>Tool ran and returned an error.</p></div></div>
          </section>
        </div>

        <RunOverview run={run} scenario={runScenario} onInspect={() => inspect('workflow')}/>

        <section className="panel results-panel" id="results">
          <div className="results-heading"><span className="step">3</span><div><h2>{run?.result ? 'Inspect the actual results' : 'Explore the workflow'}</h2><p>{run?.result ? runScenario?.title : 'Preset inputs and execution steps. Outputs appear only after execution.'}</p></div><Badge>{run?.result ? 'OBSERVED' : 'PREVIEW'}</Badge></div>
          <div className="tabs" role="tablist" aria-label="Run details">{TABS.map(([id, title]) => <button key={id} role="tab" aria-selected={tab === id} tabIndex={tab === id ? 0 : -1} aria-controls={`panel-${id}`} id={`tab-${id}`} className={tab === id ? 'selected' : ''} onClick={() => setTab(id)} onKeyDown={event => {
            if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault(); const current = TABS.findIndex(([value]) => value === id);
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? TABS.length - 1 : (current + (event.key === 'ArrowRight' ? 1 : -1) + TABS.length) % TABS.length;
            setTab(TABS[next][0]); document.getElementById(`tab-${TABS[next][0]}`)?.focus();
          }}>{title}</button>)}</div>
          <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} className="result-content">
            {tab === 'workflow' ? <WorkflowView scenario={runScenario} run={run}/> : <RunResults tab={tab} run={run} scenario={runScenario} busy={busy}/>}
          </div>
        </section>
        <details className="reading-guide"><summary>How to read findings, decisions and evidence</summary><div><article><h3>Detector finding</h3><p>What B0, B1 or B2 concludes from its permitted history. Shadow findings do not control this demo's dispatch.</p></article><article><h3>Controller decision</h3><p>Whether the host actually allowed dispatch under its permission and persistence rules.</p></article><article><h3>Evidence inspection</h3><p>Whether the recorded package passes structure, signature, context and reproduction checks.</p></article><article><h3>Run acceptance</h3><p>A separate submission check against registered expectations. Acceptance does not mean every action was safe.</p></article></div></details>
        <footer className="page-footer"><span>Local MCP testbed · synthetic data only</span><span>Engineering demonstration, not a universal protection claim</span></footer>
      </main>
    </div>
  </div>;
}
