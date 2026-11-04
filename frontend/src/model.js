export const DETECTORS = ['B0', 'B1', 'B2-R', 'B2-S'];
export const isActive = run => ['queued', 'running'].includes(run?.status);
export const auditRecords = run => run?.result?.evidence?.package?.records ?? [];
export const decisions = run => auditRecords(run).map(entry => entry.event)
  .filter(event => event.event_type === 'DISPATCH_DECISION');

export function outputState(output) {
  if (output.response?.error?.code === -32003) return { label: 'POLICY DENIED', tone: 'amber' };
  if (output.response?.error) return { label: 'PROTOCOL ERROR', tone: 'amber' };
  if (!output.response?.result) return { label: 'NO RESPONSE', tone: '' };
  if (output.response.result.isError) return { label: 'TOOL ERROR', tone: 'coral' };
  return { label: 'RETURNED', tone: 'green' };
}
export function findings(run, detector) {
  return auditRecords(run).map(entry => entry.event)
    .filter(event => event.event_type === 'DETECTOR_FINDING' && event.body.detector_id === detector);
}
export function outputs(run) {
  const report = run?.result?.report;
  if (!report) return [];
  if (report.assessor_journal) {
    const { issued_requests: requests, responses } = report.assessor_journal;
    return requests.filter(r => r.method === 'tools/call').map(request => ({
      request_id: request.id, tool: request.params.name, arguments: request.params.arguments,
      response: responses.find(r => r.id === request.id),
    }));
  }
  return [['success', 'echo'], ['controlled_error', 'controlled_failure'], ['success_after_error', 'echo']]
    .filter(([key]) => report[key]).map(([key, tool]) => ({
      tool, step_id: key, response: { result: { isError: report[key].isError, content: [{ type: 'text', text: report[key].text }] } },
    }));
}

export function observedStep(step, run) {
  if (step.kind === 'tool') {
    const output = outputs(run).find(item => item.request_id === step.id || item.step_id === step.id);
    if (!output) return null;
    const proposal = auditRecords(run).map(r => r.event).find(event =>
      event.event_type === 'CALL_PROPOSAL' && event.body.request_id === output.request_id);
    const decision = proposal && decisions(run).find(event => event.call_id === proposal.call_id);
    return { output, decision, state: outputState(output) };
  }
  const event = auditRecords(run).map(r => r.event).find(event => {
    const sameScope = ['resource', 'destination', 'release'].every(key => event.body.scope?.[key] === step.scope?.[key]);
    if (step.kind === 'grant') return event.event_type === 'GRANT' && event.body.grant_id === step.grant_id && sameScope;
    if (step.kind === 'revoke') return event.event_type === 'REVOKE_SCOPE' && sameScope;
    return false;
  });
  return event ? { event, state: { label: 'COMMITTED', tone: 'green' } } : null;
}

export function resultText(output) {
  if (output?.response?.error) return output.response.error.message;
  return output?.response?.result?.content?.map(item => item.text ?? JSON.stringify(item)).join('\n') ?? 'No response recorded.';
}
export function time(value) {
  return value ? new Date(value).toLocaleTimeString([], { hour12: false }) : '—';
}
