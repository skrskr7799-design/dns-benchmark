import {useState} from 'react'
import {useMutation} from '@tanstack/react-query'
import {api,type Family,type Inspection,type InspectionResult,type RRset} from '../shared/api'
import {fmt} from '../shared/results'
const types=['A','AAAA','CNAME','MX','TXT','NS','SOA','CAA','PTR','SRV','HTTPS','SVCB','DS','DNSKEY','RRSIG']
const labels:Record<string,string>={answer:'Ответ',no_data:'Нет записи',nxdomain:'NXDOMAIN',dns_error:'Ошибка DNS',transport_error:'Ошибка транспорта',truncated:'Усечённый ответ',alias_only:'Только CNAME',referral:'Referral'}
function Section({name,rows}:{name:string;rows:RRset[]}){
 return <details open={name==='Answer'} className="dns-section"><summary>{name} · {rows.length}</summary>{rows.length?<div className="table-wrap"><table><thead><tr><th>Имя</th><th>Тип / класс</th><th>TTL, с</th><th>Значение</th></tr></thead><tbody>{rows.map((r,i)=><tr key={i}><td>{r.name}</td><td>{r.type} / {r.class}</td><td>{r.ttl}</td><td>{r.values.map((v,j)=><div className="dns-value" key={j}>{v}</div>)}</td></tr>)}</tbody></table></div>:<p className="muted">Нет записей.</p>}</details>
}
function Resolver({r}:{r:InspectionResult}){
 return <section className="panel dns-result"><div className="section-title"><h2 className="dns-value">{r.endpoint}</h2><span className={'status '+(r.outcome==='answer'?'ok':r.error?'fail':'partial')}>{labels[r.outcome]??r.outcome}</span></div>
 <div className="dns-meta"><div><small>IP / протокол</small><b>{r.ip??'—'} · {r.protocol??'—'}</b><small>Peer: {r.peer_ip??'—'}</small></div><div><small>Запрос, мс</small><b>{fmt(r.duration_ms)}</b><small>Bootstrap: {fmt(r.bootstrap_ms)} мс</small></div><div><small>RCODE</small><b>{r.rcode??'—'}</b><small>Группа: {r.comparison_group??'—'}</small></div></div>
 {r.error&&<p className="error">{r.error}</p>}{r.fallback&&<p>UDP → TCP: ответ был усечён.</p>}
 <p>Флаги: {r.flags.join(' · ')||'—'} · EDNS: {r.edns?'v'+r.edns.version+' / '+r.edns.payload+' B':'—'}</p>
 {r.dnssec&&<p>DNSSEC: DO запроса {r.dnssec.requested_do?'1':'0'} · DO ответа {r.dnssec.response_do?'1':'0'} · AD {r.dnssec.ad?'1':'0'} · CD {r.dnssec.cd?'1':'0'}. Проверка цепочки доверия не выполнялась.</p>}
 {r.cname_chain.length>0&&<div className="dns-value"><b>CNAME в ответе</b>{r.cname_chain.map((c,i)=><div key={i}>{c.name} → {c.target}</div>)}</div>}
 <Section name="Answer" rows={r.answer}/><Section name="Authority" rows={r.authority}/><Section name="Additional" rows={r.additional}/></section>
}
function download(result:Inspection){const url=URL.createObjectURL(new Blob([JSON.stringify(result,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='dns-inspection.json';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)}
export function Inspector(){
 const [name,setName]=useState('example.com'),[qtype,setType]=useState('A'),[family,setFamily]=useState<Family>('ipv4'),[endpoints,setEndpoints]=useState('https://cloudflare-dns.com/dns-query\nhttps://dns.google/dns-query'),[dnssec,setDnssec]=useState(false),[cd,setCd]=useState(false),[fallback,setFallback]=useState(false)
 const targets=endpoints.split('\n').map(s=>s.trim()).filter(Boolean)
 const run=useMutation({mutationFn:()=>api.inspect({name:name.trim(),qtype,family,endpoints:targets,dnssec,checking_disabled:cd,tcp_fallback:fallback})})
 const result=run.data
 return <><header className="page-heading"><div><div className="eyebrow">NETWORK TOOLS / DNS</div><h1>DNS Inspector</h1><p>Записи, флаги и сравнение ответов резолверов.</p></div></header>
 <section className="panel"><form onSubmit={e=>{e.preventDefault();run.mutate()}}><div className="form-grid inspector-form"><label>Домен или IP для PTR<input required maxLength={253} value={name} onChange={e=>setName(e.target.value)} disabled={run.isPending}/></label><label>Тип записи<select value={qtype} onChange={e=>setType(e.target.value)} disabled={run.isPending}>{types.map(t=><option key={t}>{t}</option>)}</select></label><label>Сеть<select value={family} onChange={e=>setFamily(e.target.value as Family)} disabled={run.isPending}><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option><option value="auto">Auto</option></select></label></div>
 <label htmlFor="inspector-endpoints">Резолверы · {targets.length}/4</label><textarea id="inspector-endpoints" rows={4} value={endpoints} onChange={e=>setEndpoints(e.target.value)} disabled={run.isPending} spellCheck={false}/>
 <div className="controls dns-checks"><label><input type="checkbox" checked={dnssec} onChange={e=>setDnssec(e.target.checked)} disabled={run.isPending}/> DNSSEC / DO</label><label><input type="checkbox" checked={cd} onChange={e=>setCd(e.target.checked)} disabled={run.isPending}/> CD</label><label><input type="checkbox" checked={fallback} onChange={e=>setFallback(e.target.checked)} disabled={run.isPending}/> UDP → TCP при TC</label></div>
 <button disabled={run.isPending||!name.trim()||targets.length<1||targets.length>4}>{run.isPending?'Выполняется…':'Проверить DNS'}</button></form>{run.isError&&<p className="error" role="alert">{run.error.message}</p>}</section>
 {result&&<><section className="panel"><div className="section-title"><h2>{result.name} · {result.qtype}</h2><button className="secondary" onClick={()=>download(result)}>Экспорт JSON</button></div><p>{result.agreement==null?'Недостаточно ответов для сравнения':result.agreement?'Ответы совпадают по RCODE и данным':'Обнаружены различия в ответах'} · {result.comparable} сопоставимых ответов · {result.groups} групп</p><small>TTL и порядок записей не влияют на группы. Различия могут быть нормальными для CDN, кеша или политики резолвера; это не доказательство блокировки или подмены.</small></section>{result.results.map((r,i)=><Resolver key={i} r={r}/>)}</>}</>
}
