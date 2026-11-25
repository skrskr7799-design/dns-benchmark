export type Mode = 'cold' | 'warm' | 'both'
export type Family = 'ipv4' | 'ipv6' | 'auto'
export interface Result {
  endpoint: string; ip?: string | null; mode?: Mode; family?: Family;
  ok: number; count: number; mean: number | null; p50: number | null;
  p95: number | null; p99: number | null; jitter: number | null;
  error?: string; errors?: Record<string, number>; engine?: string; protocols?: string[]; peer_ips?: string[]; reuse?: {yes:number;no:number;unknown:number}; warmup_error?: string | null; requested_count?:number; bootstrap_ms?:number; bootstrap_error?:string|null
}
export interface Run { endpoints: string[]; count: number; mode: Mode; family: Family; parallel: number }
export interface Profile { id: string; name: string; config: Run }
export interface Status { running: boolean; run_id?: string; state?: string; revision?:number; results: Result[]; done: number; total: number; error?: string }
export interface History { time: number; run_id?:string; results: Result[] }
export interface Sample {index:number;peer_ip:string|null;endpoint:string;mode:Mode;domain:string;ok:boolean;duration_ms:number|null;connect_ms:number|null;handshake_ms:number|null;protocol:string|null;reused:boolean|null;rcode:string|null;error:string|null}
export interface SamplePage {total:number;offset:number;items:Sample[]}
export interface RRset {name:string;type:string;class:string;ttl:number;values:string[]}
export interface InspectionResult {endpoint:string;ip:string|null;bootstrap_ms:number;duration_ms:number|null;protocol:string|null;peer_ip:string|null;error:string|null;rcode:string|null;flags:string[];edns:{version:number;payload:number}|null;dnssec:{requested_do:boolean;response_do:boolean;ad:boolean;cd:boolean;independently_validated:boolean}|null;answer:RRset[];authority:RRset[];additional:RRset[];cname_chain:{name:string;target:string}[];fallback:boolean;outcome:string;comparison_group:number|null}
export interface Inspection {name:string;qtype:string;results:InspectionResult[];comparable:number;groups:number;agreement:boolean|null;note:string}
export interface InspectConfig {name:string;qtype:string;family:Family;endpoints:string[];dnssec:boolean;checking_disabled:boolean;tcp_fallback:boolean}
export type NetFamily='ipv4'|'ipv6'|'both'
export type NetKind='tcp'|'http'|'https'|'icmp'
export interface NetTarget {host:string;port:number;family:NetFamily}
export interface NetConfig extends NetTarget {kind:NetKind;path:string;count:number}
export interface Certificate {subject:string;issuer:string;serial:string;not_before:string;not_after:string;days_remaining:number;sha256:string;san:string[]}
export interface NetworkProbe {host:string;port:number;family:string;ip:string|null;peer_ip:string|null;source_ip:string|null;dns_ms:number|null;connect_ms:number|null;handshake_ms:number|null;ttfb_ms:number|null;headers_ms:number|null;total_ms:number|null;http_status:number|null;tls_version:string|null;alpn:string|null;cipher:string|null;certificate:Certificate|null;chain:Certificate[]|null;verified:boolean|null;stage:string;error:string|null;ok:boolean}
export interface PingResult {family:string;ip:string|null;source_ip:string|null;dns_ms:number|null;samples:{ok:boolean;duration_ms:number|null;error:string|null}[];available:boolean;error:string|null;sent:number;received:number;loss_pct:number|null;mean_ms:number|null;variation_ms:number|null}
export interface NetworkGroup {family:string;ip:string|null;samples:NetworkProbe[];attempted:number;success:number;mean_ms:number|null;variation_ms:number|null}
export interface NetworkReport {host:string;kind:NetKind;vantage:string;results:(PingResult|NetworkGroup)[]}
export interface TLSReport {host:string;vantage:string;results:NetworkProbe[]}
export interface RouteConfig {host:string;family:NetFamily;max_hops:number;attempts:number}
export interface RouteSample {status:string;address:string|null;rtt_ms:number|null;icmp_type:number|null;icmp_code:number|null;errno:number|null;error:string|null}
export interface RouteResult {family:string;ip:string|null;dns_ms:number|null;available:boolean;reached:boolean;hops:{ttl:number;samples:RouteSample[]}[];error:string|null}
export interface RouteReport {host:string;method:string;vantage:string;results:RouteResult[]}
export interface Session { authenticated: boolean; csrf: string | null }
let csrf: string | null = null
export function setSession(session: Session) { csrf=session.csrf }
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers=new Headers(init?.headers)
  if(init?.method && !['GET','HEAD'].includes(init.method)){headers.set('X-NDC-Request','1');if(csrf)headers.set('X-CSRF-Token',csrf)}
  const response = await fetch(path, {...init,headers,credentials:'same-origin'})
  if(response.status===401 && !path.startsWith('/api/auth/'))window.dispatchEvent(new Event('ndc:unauthorized'))
  if (!response.ok) {
    const body = await response.text()
    throw new Error(body || 'HTTP ' + response.status)
  }
  if(response.status===204)return undefined as T
  return response.json() as Promise<T>
}
export const api = {
  routes:(config:RouteConfig)=>request<RouteReport>('/api/v1/network/routes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(config)}),
  capabilities:()=>request<{icmp:{ipv4:boolean;ipv6:boolean};routes:{ipv4:boolean;ipv6:boolean}}>('/api/v1/capabilities'),
  connectivity:(config:NetConfig)=>request<NetworkReport>('/api/v1/network/connectivity',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(config)}),
  tls:(config:NetTarget)=>request<TLSReport>('/api/v1/network/tls',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(config)}),
  inspect:(config:InspectConfig)=>request<Inspection>('/api/v1/dns/inspect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(config)}),
  session: () => request<Session>('/api/auth/session'),
  login: (password: string) => request<Session>('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})}),
  logout: () => request<Session>('/api/auth/logout',{method:'POST'}),
  defaults: () => request<string[]>('/api/defaults'),
  status: () => request<Status>('/api/status'),
  samples: (id:string,offset:number) => request<SamplePage>('/api/v1/runs/'+encodeURIComponent(id)+'/samples?offset='+offset+'&limit=200'),
  history: () => request<History[]>('/api/history'),
  profiles: () => request<Profile[]>('/api/v1/profiles'),
  saveProfile: (name: string, config: Run) => request<Profile>('/api/v1/profiles',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,config})}),
  deleteProfile: (id: string) => request<void>('/api/v1/profiles/'+encodeURIComponent(id),{method:'DELETE'}),
  cancel: (id: string) => request<unknown>('/api/v1/runs/'+encodeURIComponent(id)+'/cancel',{method:'POST'}),
  start: (run: Run) => request<{started: boolean}>('/api/run', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(run)})
}
export function exportJson(results: Result[]) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(results,null,2)],{type:'application/json'}))
  const a = document.createElement('a'); a.href=url; a.download='dns-results.json'
  document.body.append(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000)
}
