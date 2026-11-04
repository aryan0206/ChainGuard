// Browserless rendering checks using explicit fixtures, never product demo data.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

let server;
let RunResults;
let WorkflowView;
let Walkthrough;
before(async () => {
  server = await createServer({ server: { middlewareMode: true, hmr: false, ws: false }, appType: 'custom' });
  RunResults = (await server.ssrLoadModule('/src/components/RunResults.jsx')).default;
  WorkflowView = (await server.ssrLoadModule('/src/components/WorkflowView.jsx')).WorkflowView;
  Walkthrough = (await server.ssrLoadModule('/src/components/Walkthrough.jsx')).default;
});
after(async () => { await server?.close(); });
const render = props => renderToStaticMarkup(React.createElement(RunResults, props));

test('denied calls render as denials and tool text is escaped', () => {
  const run = { result: { report: { assessor_journal: {
    issued_requests: [
      { id: 'denied', method: 'tools/call', params: { name: 'send_sink', arguments: { payload: 'synthetic' } } },
      { id: 'echo', method: 'tools/call', params: { name: 'echo', arguments: { token: 'synthetic' } } },
    ],
    responses: [
      { id: 'denied', error: { code: -32003, message: 'M6 authorization denied' } },
      { id: 'echo', result: { isError: false, content: [{ text: '<script>synthetic</script>' }] } },
    ],
  } } } };
  const html = render({ tab: 'outputs', run });
  assert.match(html, /POLICY DENIED/);
  assert.match(html, /The controller refused dispatch/);
  assert.match(html, /&lt;script&gt;synthetic&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<script>/);
});

test('M6 renders seven dimensions, actual acceptance and duplicate rejection separately', () => {
  const names = ['package_schema', 'commitment_integrity', 'trusted_signature', 'expected_binding', 'inventory_completeness', 'lifecycle_semantics', 'finding_reproduction'];
  const run = { result: { report: { duplicate_submission: { status: 'REJECTED', reason: 'ALREADY_ACCEPTED' } }, evidence: {
    package: { commitment: {}, records: [] },
    verification: { fresh_submission: 'NOT_CHECKED', dimensions: Object.fromEntries(names.map(name => [name, { status: 'PASS', reason: 'fixture' }])) },
    acceptance: { status: 'ACCEPTED', reason: 'FRESH_COMPLETE_RUN', registry_durability: 'COMMITTED' },
  } } };
  const html = render({ tab: 'audit', run });
  for (const name of names) assert.ok(html.includes(name.replaceAll('_', ' ')), name);
  assert.match(html, /Complete-run acceptance/);
  assert.match(html, /ACCEPTED/);
  assert.match(html, /Registry: COMMITTED/);
  assert.match(html, /Duplicate submission after registry reopen/);
  assert.match(html, /ALREADY_ACCEPTED/);
});

test('M4 inspection does not gain an acceptance claim', () => {
  const run = { result: { report: {}, evidence: {
    package: { commitment: {}, records: [] }, verification: { dimensions: {} },
    acceptance: { status: 'NOT_CHECKED', reason: 'M4 inspection does not perform M5 fresh submission.' },
  } } };
  const html = render({ tab: 'audit', run });
  assert.match(html, /NOT_CHECKED/);
  assert.doesNotMatch(html, />ACCEPTED</);
  assert.doesNotMatch(html, /Duplicate submission after registry reopen/);
});

test('authorization view uses controller decisions rather than detector verdicts', () => {
  const run = { result: { report: {}, evidence: { package: { records: [
    { event: { event_id: 'controller', seq: 4, event_type: 'DISPATCH_DECISION', body: { dispatch_decision: 'DENY', authorization_assessment: 'UNAUTHORIZED', reason: 'Permission unavailable' } } },
    { event: { event_id: 'shadow', event_type: 'DETECTOR_FINDING', body: { detector_id: 'B0', behavioral_verdict: 'ALLOW' } } },
  ] }, acceptance: { status: 'NOT_CHECKED', reason: 'fixture' } } } };
  const html = render({ tab: 'authorization', run });
  assert.match(html, /UNAUTHORIZED/);
  assert.match(html, /Permission unavailable/);
  assert.match(html, />DENY</);
  assert.doesNotMatch(html, />ALLOW</);
});

test('workflow preview shows inputs and no predicted output', () => {
  const scenario = { title: 'Synthetic fixture', workflow: [{ id: 'read', kind: 'tool', tool: 'read_secret_a', arguments: {}, title: 'Read a source', why: 'Preset source access.', expected: 'PREDICTED_OUTPUT_SENTINEL' }] };
  const html = renderToStaticMarkup(React.createElement(WorkflowView, { scenario, run: null }));
  assert.match(html, /Preset input/);
  assert.match(html, /Run the demonstration to see its actual output/);
  assert.match(html, /PLANNED/);
  assert.doesNotMatch(html, /PREDICTED_OUTPUT_SENTINEL|Expected outcome|RETURNED|COMMITTED/);
});

test('a missing result is not represented as an observed step', () => {
  const scenario = { title: 'Synthetic fixture', workflow: [{ id: 'missing', kind: 'grant', grant_id: 'not-seen', scope: {}, title: 'Host control', why: 'Preset control.' }] };
  const html = renderToStaticMarkup(React.createElement(WorkflowView, { scenario, run: { status: 'completed', result: { report: {}, evidence: { package: { records: [] } } } } }));
  assert.match(html, /NOT OBSERVED/);
  assert.match(html, /No recorded result is available/);
  assert.doesNotMatch(html, /Permission change committed|COMMITTED/);
});

test('walkthrough distinguishes runnable scenarios from milestone explanations', () => {
  const html = renderToStaticMarkup(React.createElement(Walkthrough));
  for (const milestone of ['M2', 'M3', 'M4', 'M5', 'M6']) assert.ok(html.includes(milestone));
  assert.match(html, /replay CLI only/);
  assert.match(html, /full M5 campaign is CLI only/);
  assert.match(html, /This site launches M1, M4 and a fresh M6.4 scenario/);
});
