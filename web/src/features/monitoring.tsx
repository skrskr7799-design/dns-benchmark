import {useState} from 'react'
import {useQuery,useMutation,useQueryClient} from '@tanstack/react-query'
import {api,type MonitorConfig,type Monitor} from '../shared/api'
import {fmt} from '../shared/results'
const time=(v:number|null)=>v==null?'—':new Date(v*1000).toLocaleString('ru-RU')
const initial:MonitorConfig={name:'',host:'example.com',port:443,family:'ipv4',kind:'https',path:'/',count:1,endpoint:'https://cloudflare-dns.com/dns-query',interval_seconds:300,failure_count:3,recovery_count:2,latency_ms:null,expiry_days:14,enabled:true,notify:false}
function History({id}:{id:string}){
 const q=useQuery({queryKey:['monitor-history',id],queryFn:()=>api.monitorHistory(id),refetchInterval:5000})
 const rows=q.data??[],max=Math.max(1,...rows.map(x=>x.latency_ms??0))
 const observed=rows.filter(x=>x.outcome!=='unknown')
 const healthy=observed.filter(x=>x.outcome==='healthy'||x.outcome==='degraded').length
 return <section className="panel"><h2>История проверок</h2>{q.isError?<p role="alert">{q.error.message}</p>:q.isPending?<p>Загрузка…</p>:!rows.length?<p>Проверок ещё нет.</p>:<><p>Успешные ответы: {observed.length?(100*healthy/observed.length).toFixed(1)+'%':'—'} · {observed.length} известных результатов. Не непрерывный uptime.</p><div className="sample-chart" role="img" aria-label="История задержек">{[...rows].reverse().map((x,i)=><div className={'sample-bar '+(x.outcome==='healthy'?'':'sample-error')} key={i} title={time(x.at)+' · '+x.outcome+' · '+fmt(x.latency_ms)} style={{height:x.latency_ms==null?'2%':Math.max(2,100*x.latency_ms/max)+'%'}}/>)}</div><div className="table-wrap"><table><thead><tr><th>Время</th><th>Результат</th><th>Задержка, мс</th><th>Причина</th></tr></thead><tbody>{rows.map((x,i)=><tr key={i}><td>{time(x.at)}</td><td>{x.outcome}</td><td>{fmt(x.latency_ms)}</td><td>{x.reason??'—'}</td></tr>)}</tbody></table></div></>}</section>
}
export function Monitoring(){
 const client=useQueryClient(),q=useQuery({queryKey:['monitoring'],queryFn:api.monitoring,refetchInterval:5000})
 const [cfg,setCfg]=useState(initial),[selected,setSelected]=useState(''),[remove,setRemove]=useState('')
 const set=<K extends keyof MonitorConfig>(k:K,v:MonitorConfig[K])=>setCfg(old=>({...old,[k]:v}))
 const refresh=()=>client.invalidateQueries({queryKey:['monitoring']})
 const create=useMutation({mutationFn:()=>api.createMonitor(cfg),onSuccess:m=>{setSelected(m.id);setCfg(old=>({...old,name:''}));void refresh()}})
 const toggle=useMutation({mutationFn:(m:Monitor)=>api.enableMonitor(m.id,!m.enabled),onSuccess:refresh})
 const del=useMutation({mutationFn:api.deleteMonitor,onSuccess:()=>{setRemove('');setSelected('');void refresh()}})
 const data=q.data,rows=data?.monitors??[]
 return <><header className="page-heading"><div><div className="eyebrow">WORKSPACE / MONITORING</div><h1>Monitoring</h1><p>Периодические проверки и журнал инцидентов.</p></div></header>
 <div className="stats">{[['Мониторы',rows.length],['Активные',rows.filter(m=>m.enabled).length],['Открытые инциденты',rows.filter(m=>m.state==='incident').length]].map(([n,v])=><div className="panel metric" key={n}><span>{n}</span><strong>{data?v:'—'}</strong></div>)}</div>
 <section className="panel"><h2>Новый монитор</h2><form onSubmit={e=>{e.preventDefault();create.mutate()}}><div className="form-grid">
 <label>Название<input required maxLength={100} value={cfg.name} onChange={e=>set('name',e.target.value)}/></label>
 <label>Хост / DNS-имя<input required value={cfg.host} onChange={e=>set('host',e.target.value)}/></label>
 <label>Тип проверки<select aria-label="Тип проверки" value={cfg.kind} onChange={e=>{const k=e.target.value as MonitorConfig['kind'];setCfg(old=>({...old,kind:k,port:k==='http'?80:443}))}}>{['tcp','http','https','tls','dns'].map(k=><option key={k}>{k}</option>)}</select></label>
 <label>Сеть<select aria-label="Сеть" value={cfg.family} onChange={e=>set('family',e.target.value as MonitorConfig['family'])}><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select></label>
 {cfg.kind==='dns'?<label>DNS endpoint<input value={cfg.endpoint} onChange={e=>set('endpoint',e.target.value)}/></label>:<label>Порт<input type="number" min={1} max={65535} value={cfg.port} onChange={e=>set('port',Number(e.target.value))}/></label>}
 {(cfg.kind==='http'||cfg.kind==='https')&&<label>HTTP путь<input value={cfg.path} onChange={e=>set('path',e.target.value)}/></label>}
 <label>Интервал, сек<input type="number" min={60} max={86400} value={cfg.interval_seconds} onChange={e=>set('interval_seconds',Number(e.target.value))}/></label>
 <label>Ошибок до инцидента<input type="number" min={1} max={10} value={cfg.failure_count} onChange={e=>set('failure_count',Number(e.target.value))}/></label>
 <label>Успехов до восстановления<input type="number" min={1} max={10} value={cfg.recovery_count} onChange={e=>set('recovery_count',Number(e.target.value))}/></label>
 <label>Порог задержки, мс<input type="number" min={1} max={60000} placeholder="Не задан" value={cfg.latency_ms??''} onChange={e=>set('latency_ms',e.target.value?Number(e.target.value):null)}/></label>
 {(cfg.kind==='tls'||cfg.kind==='https')&&<label>Сертификат, дней<input type="number" min={1} max={90} value={cfg.expiry_days} onChange={e=>set('expiry_days',Number(e.target.value))}/></label>}</div>
 <div className="controls dns-checks"><label><input type="checkbox" checked={cfg.enabled} onChange={e=>set('enabled',e.target.checked)}/> Включить</label><label><input type="checkbox" checked={cfg.notify} disabled={!data?.telegram_enabled} onChange={e=>set('notify',e.target.checked)}/> Telegram</label><small>{data?.telegram_enabled?'Telegram настроен':'Telegram не настроен'}</small></div><button disabled={create.isPending||!cfg.name.trim()||!cfg.host.trim()}>Создать монитор</button></form></section>
 {(q.isError||create.isError||toggle.isError||del.isError)&&<p className="error" role="alert">{q.error?.message||create.error?.message||toggle.error?.message||del.error?.message}</p>}
 <section className="panel"><h2>Мониторы</h2>{!rows.length?<p>Нет мониторов.</p>:<div className="table-wrap"><table><thead><tr><th>Имя / цель</th><th>Статус</th><th>Последняя проверка</th><th>Следующая</th><th>Действия</th></tr></thead><tbody>{rows.map(m=><tr key={m.id}><td><button className="secondary" onClick={()=>setSelected(m.id)}>{m.config.name}</button><div>{m.config.host} · {m.config.kind}</div></td><td>{!m.enabled?'Пауза':m.running?'Проверка':m.state}<div><small>{m.last_result?.outcome??'—'}</small></div></td><td>{time(m.last_at)}<div>{fmt(m.last_result?.latency_ms)} мс</div></td><td>{m.enabled?time(m.next_at):'—'}</td><td><button className="secondary" disabled={toggle.isPending||(!m.enabled&&m.running)} onClick={()=>toggle.mutate(m)}>{m.enabled?'Пауза':'Включить'}</button> <button className="secondary" disabled={m.running||del.isPending} onClick={()=>setRemove(m.id)}>Удалить</button></td></tr>)}</tbody></table></div>}{remove&&<div className="controls"><span>Удалить монитор, историю и инциденты?</span><button onClick={()=>del.mutate(remove)} disabled={del.isPending}>Подтвердить удаление</button><button className="secondary" onClick={()=>setRemove('')}>Отмена</button></div>}</section>
 {selected&&rows.some(m=>m.id===selected)&&<History key={selected} id={selected}/>}
 <section className="panel"><h2>Инциденты</h2>{data?.incidents.length?<div className="table-wrap"><table><thead><tr><th>Монитор</th><th>Открыт</th><th>Закрыт</th><th>Причина</th></tr></thead><tbody>{data.incidents.map(i=><tr key={i.id}><td>{rows.find(m=>m.id===i.monitor_id)?.config.name??i.monitor_id}</td><td>{time(i.opened)}</td><td>{time(i.closed)}</td><td>{i.reason}</td></tr>)}</tbody></table></div>:<p>Нет зарегистрированных инцидентов.</p>}<p>Telegram: {Object.entries(data?.delivery??{}).map(([k,v])=>k+': '+v).join(' · ')||'нет сообщений'}</p></section></>
}
