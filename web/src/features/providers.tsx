import {useState} from 'react'
import {useQuery} from '@tanstack/react-query'
import {useNavigate} from '@tanstack/react-router'
import {api,type Result} from '../shared/api'
import {useStatus} from './benchmark'
import {fmt} from '../shared/results'
import {Icon} from '../shared/identity'
const protocols:Record<string,string>={udp:'UDP',tcp:'TCP',https:'DoH2',h3:'DoH3',tls:'DoT',quic:'DoQ'}
function describe(endpoint:string){
 try{const u=new URL(endpoint);return {host:u.hostname,protocol:protocols[u.protocol.slice(0,-1)]??u.protocol.slice(0,-1)}}catch{return {host:endpoint,protocol:'—'}}
}
function full(r:Result){return r.count>0&&r.ok===r.count&&r.count===(r.requested_count??r.count)&&!r.warmup_error}
export function Providers(){
 const defaults=useQuery({queryKey:['defaults'],queryFn:api.defaults}),status=useStatus(),history=useQuery({queryKey:['history'],queryFn:api.history})
 const navigate=useNavigate()
 const [search,setSearch]=useState(''),[protocol,setProtocol]=useState('all'),[mode,setMode]=useState('cold'),[sort,setSort]=useState('name'),[selected,setSelected]=useState<string[]>([]),[error,setError]=useState('')
 const rows=status.data?.results.length?status.data.results:history.data?.[0]?.results??[]
 const endpoints=Array.from(new Set(defaults.data??[]))
 const catalog=endpoints.map(endpoint=>({endpoint,...describe(endpoint),result:rows.find(r=>r.endpoint===endpoint&&r.mode===mode)}))
 const filtered=catalog.filter(r=>(protocol==='all'||r.protocol===protocol)&&r.endpoint.toLowerCase().includes(search.toLowerCase())).sort((a,b)=>sort==='latency'?((a.result&&full(a.result)?a.result.mean:null)??Infinity)-((b.result&&full(b.result)?b.result.mean:null)??Infinity)||a.host.localeCompare(b.host):a.host.localeCompare(b.host))
 const chosen=selected.filter(e=>endpoints.includes(e))
 const featured=catalog.filter(r=>r.result&&full(r.result)&&r.result.mean!=null).sort((a,b)=>a.result!.mean!-b.result!.mean!).slice(0,4)
 function prepare(){try{localStorage.setItem('ndc.endpoints',chosen.join('\n'));void navigate({to:'/benchmark'})}catch{setError('Не удалось сохранить выбор. Разрешите локальное хранилище браузера.')}}
 return <><header className="page-heading"><div><div className="eyebrow">WORKSPACE / PROVIDERS</div><h1>DNS Providers</h1><p>Каталог доступных конфигураций DNS и результаты измерений.</p></div><button disabled={!chosen.length||chosen.length>40||status.data?.running} onClick={prepare}><Icon name="play"/> Подготовить тест · {chosen.length}</button></header>
 <div className="overview-kpis">{[['Endpoints',endpoints.length],['Hosts',new Set(catalog.map(x=>x.host)).size],['Protocols',new Set(catalog.map(x=>x.protocol)).size],['Measured',catalog.filter(x=>x.result).length]].map(([n,v])=><section className="panel metric" key={n}><span><Icon name="dns"/>{n}</span><strong>{defaults.isSuccess?v:'—'}</strong></section>)}</div>
 <div className="provider-featured">{featured.map(r=><section className="panel provider-card" key={r.endpoint}><Icon name="dns" size={26}/><b>{r.host}</b><small>{r.protocol} · {mode}</small><strong className="accent">{fmt(r.result?.mean)} мс</strong><small>P95: {fmt(r.result?.p95)} мс</small></section>)}</div>
 <section className="panel"><div className="section-title"><h2><Icon name="dns"/> Каталог резолверов</h2><small>{filtered.length} / {endpoints.length}</small></div><div className="controls"><input aria-label="Поиск провайдера" placeholder="Поиск адреса" value={search} onChange={e=>setSearch(e.target.value)}/><select aria-label="Протокол" value={protocol} onChange={e=>setProtocol(e.target.value)}><option value="all">Все протоколы</option>{Array.from(new Set(catalog.map(x=>x.protocol))).map(p=><option key={p}>{p}</option>)}</select><select aria-label="Режим измерения" value={mode} onChange={e=>setMode(e.target.value)}><option value="cold">Cold</option><option value="warm">Warm</option></select><select aria-label="Сортировка каталога" value={sort} onChange={e=>setSort(e.target.value)}><option value="name">По имени</option><option value="latency">По задержке</option></select></div>
 <p>Протокол указан по конфигурации адреса, не по подтверждённым возможностям провайдера. Измерения — текущий или последний запуск, выбранный режим.</p>
 {defaults.isError||status.isError||history.isError?<p role="alert" className="error">Часть данных недоступна.</p>:null}{error&&<p role="alert" className="error">{error}</p>}{defaults.isPending?<p>Загрузка…</p>:<div className="provider-layout"><div className="table-wrap"><table><thead><tr><th>Выбор / Endpoint</th><th>Протокол</th><th>Mean, мс</th><th>P95, мс</th><th>Успешно</th></tr></thead><tbody>{filtered.map(r=><tr key={r.endpoint}><td><label className="select-result"><input type="checkbox" aria-label={'Выбрать '+r.endpoint} checked={chosen.includes(r.endpoint)} disabled={!chosen.includes(r.endpoint)&&chosen.length>=40} onChange={e=>setSelected(old=>e.target.checked?[...old,r.endpoint]:old.filter(x=>x!==r.endpoint))}/><span className="dns-value"><b>{r.host}</b><small className="cell-note">{r.endpoint}</small></span></label></td><td><span className="protocol-chip">{r.protocol}</span></td><td>{fmt(r.result?.mean)}</td><td>{fmt(r.result?.p95)}</td><td>{r.result?r.result.ok+'/'+r.result.count:'—'}</td></tr>)}</tbody></table>{!filtered.length&&<p className="empty">Нет подходящих адресов.</p>}</div><section className="provider-comparison"><h3>Comparison · {chosen.length}</h3>{!chosen.length?<p>Выберите адреса для сравнения.</p>:catalog.filter(r=>chosen.includes(r.endpoint)).map(r=><div className="history-row" key={r.endpoint}><span className="dns-value">{r.host} · {r.protocol}</span><b>{r.result&&full(r.result)?fmt(r.result.mean)+' мс':'—'}</b></div>)}<small>Сравнение успешных полных серий. IP, семейство и режим влияют на сопоставимость.</small><button className="secondary" disabled={!chosen.length} onClick={()=>setSelected([])}>Снять выбор</button></section></div>}</section></>
}
