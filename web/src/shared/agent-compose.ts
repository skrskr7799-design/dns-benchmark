export type ComposeTrust={origin:string;ca_pem:string;sha256:string}
export type ComposeInvite={id:string;token:string;expires_at:number}
export type ComposeOptions={memory:256|384|512;restart:boolean;endpoints:string[]}
export const DNS_ENDPOINTS=["https://cloudflare-dns.com/dns-query","https://dns.google/dns-query","udp://1.1.1.1","udp://8.8.8.8"]
export function agentCompose(trust:ComposeTrust,invite:ComposeInvite,options:ComposeOptions,clean=false):string{
 const match=/^https:\/\/(100\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):8443$/.exec(trust.origin)
 if(!match)throw new Error("NetBird origin required")
 const octets=match[1].split('.').map(Number)
 if(octets[1]<64||octets[1]>127||octets.some(n=>n>255)||octets.join('.')!==match[1])throw new Error("NetBird origin required")
 if(!/^[a-f0-9]{32}$/.test(invite.id)||!(/^[A-Za-z0-9_-]{43}$/.test(invite.token))||!Number.isFinite(invite.expires_at)||invite.expires_at<=0)throw new Error("Invalid invitation")
 if(!/^[a-f0-9]{64}$/.test(trust.sha256)||trust.ca_pem.length>8192||trust.ca_pem.includes('$'))throw new Error("Invalid public CA")
 if(![256,384,512].includes(options.memory)||!options.endpoints.length||options.endpoints.some(e=>!DNS_ENDPOINTS.includes(e))||new Set(options.endpoints).size!==options.endpoints.length)throw new Error("Invalid profile")
 const payload={version:1,agent_id:invite.id,origin:trust.origin,ca_pem:trust.ca_pem,ca_sha256:trust.sha256,endpoints:options.endpoints,token:clean?"":invite.token,expires_at:clean?0:Math.floor(invite.expires_at)}
 const literal=JSON.stringify(JSON.stringify(payload))
 return [
  '# NDC agent · DNS profile · Docker Compose >= 2.23.1',
  clean?'# Registered agent: no enrollment secret. Keep the existing volume.':'# SECRET: one-use invitation. Save with mode 0600; never share or commit.',
  'name: ndc-agent-'+invite.id,
  'services:',
  '  agent:',
  '    image: ghcr.io/skrskr7799-design/dns-benchmark:edge',
  '    command: ["python","-m","backend.ndc.agent_client"]',
  '    environment:',
  '      NDC_CONTROLLER_URL: '+JSON.stringify(trust.origin),
  '      NDC_AGENT_PROTOCOL: "2"',
  '      NDC_AGENT_MTLS: "1"',
  '      NDC_AGENT_CA_FILE: "/data/controller-ca.pem"',
  '      NDC_AGENT_EXPECTED_ID: '+JSON.stringify(invite.id),
  '      NDC_AGENT_CA_SHA256: '+JSON.stringify(trust.sha256),
  '    volumes:',
  '      - agent-data:/data',
  '    healthcheck:',
  '      disable: true',
  '    pids_limit: 64',
  '    mem_limit: '+options.memory+'m',
  '    stop_grace_period: 20s',
  '    restart: '+(options.restart?'unless-stopped':'no'),
  '    security_opt:',
  '      - no-new-privileges:true',
  '    cap_drop:',
  '      - ALL',
  '    read_only: true',
  '    tmpfs:',
  '      - /tmp:size=32m',
  '  bootstrap:',
  '    image: ghcr.io/skrskr7799-design/dns-benchmark:edge',
  '    profiles: ["bootstrap"]',
  '    entrypoint: ["python","-m","backend.ndc.agent_bootstrap"]',
  '    network_mode: none',
  '    environment:',
  '      NDC_CONTROLLER_URL: '+JSON.stringify(trust.origin),
  '      NDC_AGENT_PROTOCOL: "2"',
  '      NDC_AGENT_MTLS: "1"',
  '      NDC_AGENT_CA_FILE: "/data/controller-ca.pem"',
  '    configs:',
  '      - source: bootstrap',
  '        target: /run/ndc-bootstrap.json',
  '    volumes:',
  '      - agent-data:/data',
  '    healthcheck:',
  '      disable: true',
  '    pids_limit: 32',
  '    mem_limit: 128m',
  '    restart: "no"',
  '    security_opt:',
  '      - no-new-privileges:true',
  '    cap_drop:',
  '      - ALL',
  '    read_only: false',
  'volumes:',
  '  agent-data:',
  'configs:',
  '  bootstrap:',
  '    content: '+literal,
  ''
 ].join('\n')
}
