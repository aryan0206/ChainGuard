// Explicit test fixtures; the application never loads these as runtime results.
import test from 'node:test';
import assert from 'node:assert/strict';
import { auditRecords, decisions, findings, isActive, observedStep, outputState, outputs, resultText } from './model.js';

test('empty and active states do not invent results', () => {
  assert.deepEqual(outputs(null), []);
  assert.deepEqual(auditRecords(null), []);
  assert.deepEqual(findings(null, 'B0'), []);
  assert.equal(isActive({ status: 'running' }), true);
  assert.equal(isActive({ status: 'timed_out' }), false);
});
test('M1 controlled errors remain tool errors', () => {
  const rows = outputs({ result: { report: { success: { text: '<script>test</script>', isError: false }, controlled_error: { text: 'failure', isError: true } } } });
  assert.equal(rows[0].response.result.content[0].text, '<script>test</script>');
  assert.equal(rows[1].response.result.isError, true);
  assert.equal(rows[0].request_id, undefined);
});
test('M4 responses correlate by request ID rather than response position', () => {
  const rows = outputs({ result: { report: { assessor_journal: {
    issued_requests: [{ id: 3, method: 'tools/call', params: { name: 'echo', arguments: { token: 'sample' } } }],
    responses: [{ id: 4, result: 'unrelated' }, { id: 3, result: { content: [] } }],
  } } } });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].response.id, 3);
  assert.deepEqual(rows[0].arguments, { token: 'sample' });
});
test('comparison separates actual detector findings without scores', () => {
  const record = { event: { seq: 4, event_type: 'DETECTOR_FINDING', body: { detector_id: 'B2-S', behavioral_verdict: 'ALLOW' } } };
  const run = { result: { evidence: { package: { records: [record] } } } };
  assert.equal(findings(run, 'B2-S')[0].body.behavioral_verdict, 'ALLOW');
  assert.deepEqual(findings(run, 'B0'), []);
});

test('live policy denials cannot be rendered as successful tool results', () => {
  assert.equal(outputState({ response: { error: { code: -32003 } } }).label, 'POLICY DENIED');
  assert.equal(outputState({ response: { error: { code: -32602 } } }).label, 'PROTOCOL ERROR');
  assert.equal(outputState({ response: { result: { isError: true } } }).label, 'TOOL ERROR');
  assert.equal(outputState({ response: { result: { isError: false } } }).label, 'RETURNED');
  assert.equal(outputState({}).label, 'NO RESPONSE');
});

test('controller decisions stay separate from shadow detector findings', () => {
  const run = { result: { evidence: { package: { records: [
    { event: { event_type: 'DISPATCH_DECISION', seq: 5, body: { dispatch_decision: 'DENY' } } },
    { event: { event_type: 'DETECTOR_FINDING', body: { detector_id: 'B0', behavioral_verdict: 'ALLOW' } } },
  ] } } } };
  assert.equal(decisions(run).length, 1);
  assert.equal(decisions(run)[0].body.dispatch_decision, 'DENY');
  assert.equal(findings(run, 'B0')[0].body.behavioral_verdict, 'ALLOW');
});

test('workflow uses typed request correlation and its matching controller decision', () => {
  const run = { result: { report: { assessor_journal: {
    issued_requests: [{ id: 7, method: 'tools/call', params: { name: 'send_sink', arguments: { payload: 'synthetic' } } }],
    responses: [{ id: '7', result: { content: [{ text: 'unrelated' }] } }, { id: 7, error: { code: -32003, message: 'denied' } }],
  } }, evidence: { package: { records: [
    { event: { event_type: 'CALL_PROPOSAL', call_id: 'call-7', body: { request_id: 7 } } },
    { event: { event_type: 'DISPATCH_DECISION', call_id: 'another', body: { dispatch_decision: 'ALLOW' } } },
    { event: { event_type: 'DISPATCH_DECISION', call_id: 'call-7', body: { dispatch_decision: 'DENY' } } },
  ] } } } };
  const observed = observedStep({ kind: 'tool', id: 7 }, run);
  assert.equal(observed.state.label, 'POLICY DENIED');
  assert.equal(observed.decision.body.dispatch_decision, 'DENY');
  assert.equal(resultText(observed.output), 'denied');
  assert.equal(observedStep({ kind: 'tool', id: '7' }, run), null);
});

test('grant and revocation steps require their exact committed scope', () => {
  const scope = { resource: 'secret-a', destination: 'sink', release: 'release' };
  const grant = { kind: 'grant', grant_id: 'g-1', scope };
  const run = { result: { evidence: { package: { records: [
    { event: { event_type: 'GRANT', seq: 3, body: { grant_id: 'g-1', scope: { ...scope, destination: 'other-sink' } } } },
    { event: { event_type: 'GRANT', seq: 8, body: { grant_id: 'g-1', scope } } },
    { event: { event_type: 'REVOKE_SCOPE', seq: 12, body: { scope } } },
  ] } } } };
  assert.equal(observedStep(grant, run).event.seq, 8);
  assert.equal(observedStep({ kind: 'revoke', scope }, run).event.seq, 12);
  assert.equal(observedStep({ ...grant, grant_id: 'not-committed' }, run), null);
  assert.equal(observedStep(grant, null), null);
});

test('M1 workflow links report sections without inventing protocol IDs', () => {
  const run = { result: { report: { success: { text: 'actual-token', isError: false } } } };
  const observed = observedStep({ kind: 'tool', id: 'success' }, run);
  assert.equal(resultText(observed.output), 'actual-token');
  assert.equal(observed.output.request_id, undefined);
  assert.equal(observed.decision, undefined);
});
