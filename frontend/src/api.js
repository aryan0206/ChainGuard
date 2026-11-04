export async function request(path, options = {}) {
  const response = await fetch(`/api${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', 'X-ChainGuard-Client': 'local-dashboard', ...options.headers },
  });
  let body;
  try { body = await response.json(); } catch { throw new Error('The API did not return JSON. Check that the backend is running on port 8001.'); }
  if (!response.ok) {
    const error = new Error(typeof body.detail === 'string' ? body.detail : 'The API rejected this request.');
    error.status = response.status;
    throw error;
  }
  return body;
}
