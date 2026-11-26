import {useState,useRef} from 'react'
import {useQuery,useQueryClient} from '@tanstack/react-query'
import {api,type SnapshotScope,type SnapshotProbe,type SnapshotSummary,type SnapshotField,type SnapshotDiff,type SnapshotSchedule,type SnapshotDetail} from '../shared/api'
import {Icon} from '../shared/identity'

const scopes:Record<SnapshotScope,string>={configured_monitors:'Мониторы',dns:'DNS',tls:'TLS',route:'Маршрут'}
const statuses:Record<string,string>={changed:'Изменено',unchanged:'Без изменений',unknown:'Неизвестно',not_comparable:'Несопоставимо',same_observation:'То же измерение',observed_added:'Появилось в ответе',observed_removed:'Не наблюдается в ответе',monitor_added:'Монитор добавлен',monitor_removed:'Монитор удалён',inventory_unknown:'Состав неизвестен',monitor_retained:'Монитор сохранён',fresh:'Свежая проверка',stale:'Устарело',paused:'Пауза',maintenance:'Обслуживание',not_collected:'Нет измерения',not_collected_since_boundary:'Нет новой проверки после паузы',captured:'Снимок сохранён',capacity:'Хранилище заполнено',interrupted:'Прервано перезапуском',error:'Ошибка',success:'Успешно',failure:'Сбой',partial:'Частично'}
const fields:Record<string,string>={address:'IP-адрес',resolver_ip:'IP резолвера',protocol:'Протокол',outcome:'Результат',http_status:'HTTP статус',rrset:'DNS-запись',rrsets:'DNS-записи',response_outcome:'Тип DNS-ответа',verified:'Проверка доверия',fingerprint:'SHA-256 сертификата',not_after:'Действителен до',tls_version:'Версия TLS',alpn:'ALPN',destination_reached:'Назначение достигнуто',name:'Имя',host:'Хост',enabled:'Активен',interval_seconds:'Интервал (с)',target_config_hash:'Отпечаток настроек цели',latency_ms:'Задержка (мс)',certificate_days_remaining:'Дней до истечения',observation_status:'Актуальность наблюдения'}
const date=(v:number|null|undefined)=>v==null?'—':new Date(v*1000).toLocaleString('ru-RU')
const fieldName=(v:string)=>fields[v]??(v.startsWith('ttl:')?'TTL / hop '+v.slice(4):v)
const stateName=(v:string)=>statuses[v]??v
const display=(v:unknown):string=>v==null?'—':typeof v==='boolean'?(v?'Да':'Нет'):Array.isArray(v)?(v.length?v.map(display).join('\n'):'Пустой набор'):typeof v==='object'?JSON.stringify(v,null,2):String(v)
const visible=(f:SnapshotField)=>!['unchanged','same_observation'].includes(f.status??'changed')
const compatible=(a:SnapshotSummary,b:SnapshotSummary)=>a.seq<b.seq&&a.scope===b.scope&&(a.scope==='configured_monitors'||!!a.config_key&&a.config_key===b.config_key)
function uuid(){
 const a=crypto.getRandomValues(new Uint8Array(16));a[6]=(a[6]&15)|64;a[8]=(a[8]&63)|128
 const h=Array.from(a,x=>x.toString(16).padStart(2,'0')).join('')
 return [h.slice(0,8),h.slice(8,12),h.slice(12,16),h.slice(16,20),h.slice(20)].join('-')
}
function CaptureForm({onDone}:{onDone:()=>void}){
 const [kind,setKind]=useState<SnapshotScope>('configured_monitors'),[label,setLabel]=useState(''),[host,setHost]=useState(''),[endpoint,setEndpoint]=useState(''),[qtype,setQtype]=useState('A'),[family,setFamily]=useState<'ipv4'|'ipv6'>('ipv4'),[port,setPort]=useState(443),[hops,setHops]=useState(8),[interval,setInterval]=useState(21600),[scheduled,setScheduled]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState('')
 const lock=useRef(false),retry=useRef<{key:string;id:string}|null>(null)
 async function submit(){
  if(lock.current)return
  const probe:SnapshotProbe|null=kind==='configured_monitors'?null:kind==='dns'?{kind,name:host.trim(),qtype,endpoints:[endpoint.trim()],family,dnssec:false,checking_disabled:false,tcp_fallback:false}:kind==='tls'?{kind,host:host.trim(),port,family}:{kind,host:host.trim(),family,max_hops:hops,attempts:1}
  const name=label.trim();if(!name){setError('Укажите имя снимка.');return}
  lock.current=true;setBusy(true);setError('')
  try{
   if(scheduled)await api.snapshotScheduleCreate(name,interval,probe)
   else{
    const key=JSON.stringify({name,probe})
    if(retry.current?.key!==key)retry.current={key,id:uuid()}
    await api.snapshotCreate(retry.current.id,name,probe);retry.current=null
   }
   setLabel('');onDone()
  }catch{setError(scheduled?'Не удалось создать расписание. Проверьте список перед повторной отправкой.':'Снимок не подтверждён. Проверьте настройки, доступность слота и свободное место; повтор использует тот же ID.')}
  finally{lock.current=false;setBusy(false)}
 }
 return <section className="panel tm-capture"><div className="section-title"><h2><Icon name="history"/> Новый снимок</h2><span className="tag">Controller</span></div><div className="view-tabs" role="group" aria-label="Способ создания"><button className="secondary" aria-pressed={!scheduled} onClick={()=>setScheduled(false)} disabled={busy}>Вручную</button><button className="secondary" aria-pressed={scheduled} onClick={()=>setScheduled(true)} disabled={busy}>По расписанию</button></div>
 <form onSubmit={e=>{e.preventDefault();void submit()}}><fieldset disabled={busy} className="tm-fields"><label>Название<input aria-label="Название снимка" required maxLength={80} value={label} onChange={e=>setLabel(e.target.value)} placeholder="Например, до обновления"/></label><label>Тип снимка<select aria-label="Тип снимка" value={kind} onChange={e=>setKind(e.target.value as SnapshotScope)}>{Object.entries(scopes).map(([k,v])=><option value={k} key={k}>{v}</option>)}</select></label>
 {kind!=='configured_monitors'&&<><label>{kind==='dns'?'DNS-имя':'Хост'}<input aria-label="Цель снимка" required maxLength={253} value={host} onChange={e=>setHost(e.target.value)} placeholder="example.com"/></label><label>Семейство IP<select value={family} aria-label="Семейство снимка" onChange={e=>setFamily(e.target.value as 'ipv4'|'ipv6')}><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select></label></>}
 {kind==='dns'&&<><label>Резолвер<input aria-label="Резолвер снимка" required maxLength={500} value={endpoint} onChange={e=>setEndpoint(e.target.value)} placeholder="udp://1.1.1.1"/></label><label>Тип записи<select aria-label="Тип DNS-записи" value={qtype} onChange={e=>setQtype(e.target.value)}>{['A','AAAA','CNAME','MX','NS','PTR','SOA','SRV','CAA'].map(k=><option key={k}>{k}</option>)}</select></label></>}
 {kind==='tls'&&<label>Порт<input type="number" min={1} max={65535} required value={port} onChange={e=>setPort(Number(e.target.value))}/></label>}
 {kind==='route'&&<label>Максимум переходов<input type="number" min={1} max={8} required value={hops} onChange={e=>setHops(Number(e.target.value))}/></label>}
 {scheduled&&<label>Период<select aria-label="Период снимка" value={interval} onChange={e=>setInterval(Number(e.target.value))}>{[[3600,'1 час'],[21600,'6 часов'],[43200,'12 часов'],[86400,'24 часа'],[604800,'7 дней']].map(([v,l])=><option key={v} value={v}>{l}</option>)}</select></label>}
 </fieldset><p><small>{kind==='configured_monitors'?'Сохраняются последние доступные проверки без нового сетевого запроса.':'Будет выполнена одна ограниченная проверка с контроллера. Неполный результат тоже может быть сохранён.'} {scheduled?'Первый запуск после выбранного интервала.':''}</small></p><button type="submit" disabled={busy}>{busy?'Выполняется…':scheduled?'Создать расписание':'Сохранить снимок'}</button>{error&&<p className="error" role="alert">{error}</p>}</form></section>
}
function Fields({rows,only}:{rows:SnapshotField[];only:boolean}){
 const shown=only?rows.filter(visible):rows
 return shown.length?<div className="tm-fields-list">{shown.map((f,i)=><div className="tm-diff-row" key={f.field+JSON.stringify(f.key??[])+i}><div className="tm-diff-head"><b>{fieldName(f.field)}{f.key?' · '+f.key.join(' / '):''}</b><span className={'tm-state tm-'+(f.status??'changed')}>{stateName(f.status??'changed')}</span></div><div className="tm-values"><div className={f.status==='changed'||!f.status?'tm-before':''}><small>До</small><pre>{display(f.before)}</pre></div><div className={f.status==='changed'||!f.status?'tm-after':''}><small>После</small><pre>{display(f.after)}</pre></div></div></div>)}</div>:<p>Нет изменений в выбранном фильтре.</p>
}
function Diff({data,only}:{data:SnapshotDiff;only:boolean}){
 if(data.methodology==='probe-diff-v1')return <><div className="tm-counts">{[['Изменения',data.changes.filter(f=>['changed','observed_added','observed_removed'].includes(f.status??'')).length],['Неизвестно',data.changes.filter(f=>['unknown','not_comparable'].includes(f.status??'')).length],['Без изменений',data.changes.filter(f=>f.status==='unchanged').length]].map(([k,v])=><div key={k}><small>{k}</small><strong>{v}</strong></div>)}</div><Fields rows={data.changes} only={only}/><small>Изменение DNS-ответа не доказывает изменение зоны; TTL может отражать возраст кэша. Смена узла или сертификата не доказывает причину.</small></>
 const rows=data.changes.filter(m=>!only||m.kind!=='monitor_retained'||m.settings.length>0||m.observations.some(visible)||m.before_status!==m.after_status)
 return <><div className="tm-counts">{[['Добавлено',data.changes.filter(m=>m.kind==='monitor_added').length],['Удалено',data.changes.filter(m=>m.kind==='monitor_removed').length],['Сохранено',data.changes.filter(m=>m.kind==='monitor_retained').length]].map(([k,v])=><div key={k}><small>{k}</small><strong>{v}</strong></div>)}</div>{rows.length?rows.map(m=><details className="tm-monitor-diff" key={m.monitor_id} open><summary><b>{m.after_name??m.before_name}</b><span className="tm-state">{stateName(m.kind)}</span></summary>{m.kind==='monitor_retained'&&<><p><small>{stateName(m.before_status??'unknown')} → {stateName(m.after_status??'unknown')}</small></p><Fields rows={[...m.settings.map(f=>({...f,status:'changed'})),...m.observations]} only={only}/><small>{m.before_evidence_id?'Связь с исходным измерением до: '+m.before_evidence_id.slice(0,12)+'…':''} {m.after_evidence_id?'После: '+m.after_evidence_id.slice(0,12)+'…':''}</small></>}</details>):<p>Нет изменений в выбранном фильтре.</p>}<small>Удаление монитора — изменение конфигурации, а не исчезновение устройства из сети.</small></>
}
function SnapshotView({detail}:{detail:SnapshotDetail}){
 const s=detail.snapshot
 return <div className="tm-detail"><h3>{detail.label}</h3><p><small>{date(detail.captured_at)} · {s.methodology}</small></p><p className="tm-hash">SHA-256: {detail.content_hash}</p>{s.monitors?s.monitors.length?s.monitors.map(m=><details key={m.monitor_id}><summary>{display(m.settings.name)} · {stateName(m.observation_status)}</summary><small>Последняя проверка: {date(m.last_check_at)}</small><pre>{display(m.settings)}</pre><pre>{display(m.observation)}</pre></details>):<p>В снимке нет настроенных мониторов.</p>:<><pre>{display(s.target)}</pre><pre>{display(s.observation)}</pre></>}<details><summary>Ограничения снимка</summary>{s.limitations.map(l=><p key={l}><small>{l}</small></p>)}</details></div>
}
function Schedules({rows,onDone,onSnapshot}:{rows:SnapshotSchedule[];onDone:()=>void;onSnapshot:(id:string)=>void}){
 const [busy,setBusy]=useState(''),[error,setError]=useState(''),[confirm,setConfirm]=useState('')
 const lock=useRef(false)
 async function action(row:SnapshotSchedule,remove:boolean){
  if(lock.current)return
  lock.current=true;setBusy(row.id);setError('')
  try{if(remove)await api.snapshotScheduleDelete(row.id);else await api.snapshotScheduleEnable(row.id,!row.enabled);setConfirm('');onDone()}catch{setError('Операция не выполнена. Возможно, снимок уже создаётся. Обновите состояние.')}
  finally{setBusy('');lock.current=false}
 }
 return <section className="panel tm-schedules"><div className="section-title"><h2><Icon name="clock"/> Расписания</h2><span className="tag">{rows.length} / 8</span></div>{rows.length?rows.map(r=><div className="tm-schedule" key={r.id}><div><b>{r.config.label}</b><p><small>{scopes[r.config.probe?.kind??'configured_monitors']} · каждые {r.config.interval_seconds/3600} ч · {r.running?'Выполняется':r.enabled?'Активно':'На паузе'}</small></p><small>{r.enabled?'Следующий запуск: '+date(r.next_at):'Автозапуск отключён'}</small><p><small>Последний результат: {r.last_status?stateName(r.last_status):'Ещё не запускалось'} · {r.runs} запусков / {r.errors} ошибок выполнения</small></p>{r.last_snapshot_id&&<button className="secondary" onClick={()=>onSnapshot(r.last_snapshot_id!)}>Последний снимок</button>}</div><div className="tm-actions"><button className="secondary" disabled={!!busy||r.running} onClick={()=>void action(r,false)}>{r.enabled?'Пауза':'Возобновить'}</button>{confirm===r.id?<><button className="secondary" disabled={!!busy||r.running} onClick={()=>void action(r,true)}>Подтвердить удаление</button><button className="secondary" onClick={()=>setConfirm('')}>Отмена</button></>:<button className="secondary" disabled={!!busy||r.running} onClick={()=>setConfirm(r.id)}>Удалить расписание</button>}</div></div>):<p>Расписаний пока нет. Создайте профиль в форме нового снимка.</p>}{error&&<p role="alert" className="error">{error}</p>}<small>Удаление профиля не удаляет снимки. Сохранённый снимок не означает успешное сетевое измерение.</small></section>
}
export function TimeMachine(){
 const client=useQueryClient()
 const [scope,setScope]=useState('all'),[older,setOlder]=useState(''),[newer,setNewer]=useState(''),[selected,setSelected]=useState(''),[pair,setPair]=useState<[string,string]|null>(null),[only,setOnly]=useState(true),[confirm,setConfirm]=useState(false),[deleting,setDeleting]=useState(false),[error,setError]=useState('')
 const list=useQuery({queryKey:['tm-list'],queryFn:async({signal})=>{
  const first=await api.snapshotList(undefined,signal)
  if(first.next_before!==null){const second=await api.snapshotList(first.next_before,signal);return {...first,items:[...first.items,...second.items],next_before:second.next_before}}
  return first
 },retry:false,refetchOnWindowFocus:false})
 const schedules=useQuery({queryKey:['tm-schedules'],queryFn:({signal})=>api.snapshotSchedules(signal),retry:false,refetchOnWindowFocus:false})
 const rows=list.data?.items??[],filtered=rows.filter(r=>scope==='all'||r.scope===scope)
 const a=filtered.find(r=>r.id===older),candidates=a?filtered.filter(r=>compatible(a,r)):[]
 const b=candidates.find(r=>r.id===newer)
 const detail=useQuery({queryKey:['tm-detail',selected],queryFn:({signal})=>api.snapshotDetail(selected,signal),enabled:!!selected,retry:false})
 const diff=useQuery({queryKey:['tm-diff',pair?.[0],pair?.[1]],queryFn:({signal})=>api.snapshotCompare(pair![0],pair![1],signal),enabled:!!pair,retry:false})
 const refresh=()=>{void client.invalidateQueries({queryKey:['tm-list']});void client.invalidateQueries({queryKey:['tm-schedules']})}
 const select=(id:string)=>{setSelected(id);setConfirm(false);setError('')}
 const clearPair=()=>{setPair(null)}
 async function remove(){
  if(!selected||deleting)return
  setDeleting(true);setError('')
  try{await api.snapshotDelete(selected);client.removeQueries({queryKey:['tm-detail',selected]});setSelected('');setConfirm(false);setOlder('');setNewer('');clearPair();refresh()}catch{setError('Не удалось удалить снимок. Обновите список.')}finally{setDeleting(false)}
 }
 return <><header className="page-heading"><div><div className="eyebrow">INTELLIGENCE / NETWORK HISTORY</div><h1>Network Time Machine</h1><p>Сохраняйте состояние сети и сравнивайте наблюдаемые изменения.</p></div><button className="secondary" onClick={refresh} disabled={list.isFetching||schedules.isFetching}><Icon name="clock"/> Обновить</button></header>
 {list.data&&!list.isError&&<div className="stats tm-kpis">{[['Снимки',list.data.usage.count+' / '+list.data.usage.max_count],['Хранилище',(list.data.usage.bytes/1024).toFixed(1)+' КиБ'],['Расписания',schedules.isError||!schedules.data?'—':schedules.data.length+' / 8']].map(([k,v])=><div className="panel metric" key={k}><span>{k}</span><strong>{v}</strong></div>)}</div>}
 <CaptureForm onDone={refresh}/>
 <div className="tm-layout"><section className="panel"><div className="section-title"><h2><Icon name="history"/> История снимков</h2></div><label>Тип истории<select aria-label="Фильтр истории" value={scope} onChange={e=>{setScope(e.target.value);setOlder('');setNewer('');clearPair()}}><option value="all">Все типы</option>{Object.entries(scopes).map(([k,v])=><option key={k} value={k}>{v}</option>)}</select></label>{list.isPending?<p role="status">Загрузка истории…</p>:list.isError?<p role="alert">История недоступна. <button className="secondary" onClick={()=>void list.refetch()}>Повторить</button></p>:!filtered.length?<div className="tm-empty"><Icon name="history" size={36}/><h3>Нет снимков</h3><p>Создайте первый снимок или измените фильтр.</p></div>:<div className="tm-timeline">{filtered.map(r=><button className="secondary tm-snapshot" key={r.id} aria-pressed={selected===r.id} onClick={()=>select(r.id)}><i/><span><b>{r.label}</b><small>{date(r.captured_at)} · {scopes[r.scope]}</small></span><Icon name="arrow" size={16}/></button>)}</div>}{list.data?.next_before!==null&&list.data?.next_before!==undefined&&<small>Список ограничен 200 записями; обновите при изменении хранилища.</small>}</section>
 <section className="panel"><div className="section-title"><h2>Детали снимка</h2><span className="tag">Immutable</span></div>{!selected?<p>Выберите снимок в истории.</p>:detail.isPending?<p role="status">Загрузка снимка…</p>:detail.isError?<p role="alert">Снимок недоступен или удалён.</p>:detail.data&&<><SnapshotView detail={detail.data}/>{confirm?<div className="tm-actions"><button className="secondary" disabled={deleting} onClick={()=>void remove()}>Удалить окончательно</button><button className="secondary" disabled={deleting} onClick={()=>setConfirm(false)}>Отмена</button></div>:<button className="secondary" onClick={()=>setConfirm(true)}>Удалить снимок</button>}</>}{error&&<p role="alert" className="error">{error}</p>}</section></div>
 <section className="panel tm-compare"><div className="section-title"><h2><Icon name="intelligence"/> Сравнение снимков</h2><span className="tag">Semantic diff</span></div><div className="tm-compare-pickers"><label>До<select aria-label="Снимок до" value={a?.id??''} onChange={e=>{setOlder(e.target.value);setNewer('');clearPair()}}><option value="">Выберите снимок</option>{filtered.map(r=><option key={r.id} value={r.id}>{r.label} · {date(r.captured_at)}</option>)}</select></label><Icon name="arrow"/><label>После<select aria-label="Снимок после" value={b?.id??''} disabled={!a} onChange={e=>{setNewer(e.target.value);clearPair()}}><option value="">Выберите совместимый снимок</option>{candidates.map(r=><option key={r.id} value={r.id}>{r.label} · {date(r.captured_at)}</option>)}</select></label></div><p><small>Сравнение доступно для более позднего снимка того же типа и конфигурации проверки.</small></p><div className="tm-actions"><button disabled={!a||!b||diff.isFetching} onClick={()=>setPair([a!.id,b!.id])}>Сравнить</button><label className="tm-check"><input type="checkbox" checked={only} onChange={e=>setOnly(e.target.checked)}/> Только изменения и неизвестные</label></div>{pair&&(!rows.some(r=>r.id===pair[0])||!rows.some(r=>r.id===pair[1]))?<p>Один из снимков больше не доступен.</p>:pair&&(diff.isPending?<p role="status">Сравнение…</p>:diff.isError?<p role="alert">Сравнение недоступно. Проверьте совместимость и наличие снимков.</p>:diff.data&&<Diff data={diff.data} only={only}/>)}</section>
 {schedules.isPending?<section className="panel" role="status">Загрузка расписаний…</section>:schedules.isError?<section className="panel" role="alert">Расписания недоступны. <button className="secondary" onClick={()=>void schedules.refetch()}>Повторить</button></section>:<Schedules rows={schedules.data??[]} onDone={refresh} onSnapshot={select}/>}
 <section className="panel"><h2>Ограничения истории</h2><p>Снимки отражают отдельные проверки и конфигурацию, а не непрерывную историю всех устройств. Неизвестное состояние не означает удаление. При заполнении хранилища расписания приостанавливаются без автоматического удаления снимков.</p></section></>
}
