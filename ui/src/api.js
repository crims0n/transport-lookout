const defaults = { baseUrl: localStorage.getItem('transport-lookout.baseUrl') || 'http://localhost:8080', token: localStorage.getItem('transport-lookout.token') || '' };
export const config = { ...defaults };
export function saveConfig(next) { Object.assign(config, next); localStorage.setItem('transport-lookout.baseUrl', config.baseUrl); localStorage.setItem('transport-lookout.token', config.token); }
export async function api(path, options = {}) {
  const response = await fetch(`${config.baseUrl}${path}`, { ...options, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${config.token}`, ...options.headers } });
  const body = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) throw new Error(body?.detail || `Request failed (${response.status})`);
  return body;
}
