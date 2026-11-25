export type Mode = 'cold' | 'warm'
export type Family = 'ipv4' | 'ipv6' | 'auto'
export interface Result {
  endpoint: string; ip?: string | null; mode?: Mode; family?: Family;
  ok: number; count: number; mean: number | null; p50: number | null;
  p95: number | null; p99: number | null; jitter: number | null;
  error?: string; errors?: Record<string, number>
}
export interface Run { endpoints: string[]; count: number; mode: Mode; family: Family; parallel: number }
export interface Status { running: boolean; results: Result[]; done: number; total: number; error?: string }
export interface History { time: number; results: Result[] }
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init)
  if (!response.ok) {
    const body = await response.text()
    throw new Error(body || 'HTTP ' + response.status)
  }
  return response.json() as Promise<T>
}
export const api = {
  defaults: () => request<string[]>('/api/defaults'),
  status: () => request<Status>('/api/status'),
  history: () => request<History[]>('/api/history'),
  start: (run: Run) => request<{started: boolean}>('/api/run', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(run)})
}
export function exportJson(results: Result[]) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(results,null,2)],{type:'application/json'}))
  const a = document.createElement('a'); a.href=url; a.download='dns-results.json'
  document.body.append(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000)
}
