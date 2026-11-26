import {useState,useEffect,useRef} from 'react'
import {useQuery} from '@tanstack/react-query'
import {Link} from '@tanstack/react-router'
import {api,type ObservatoryReport,type ObservatoryPoint,type ObservatoryBoundary} from '../shared/api'
import {Icon} from '../shared/identity'

const states:Record<string,string>={learning:'Обучение',normal:'Норма',candidate:'Отклонение',anomaly:'Аномалия',recovering:'Восстановление',degraded:'Деградация',unavailable:'Недоступен',unknown:'Неизвестно',stale:'Нет свежих данных',paused:'Пауза',healthy:'Норма',incident:'Инцидент',success:'Успешно',partial:'Деградация',failure:'Сбой'}
const events:Record<string,string>={'tracking.started':'Начало наблюдения','anomaly.detected':'Аномалия обнаружена','anomaly.recovered':'Аномалия завершилась','anomaly.interrupted':'Наблюдение аномалии прервано','monitor.paused':'Мониторинг приостановлен','monitor.resumed':'Мониторинг возобновлён'}
const reasons:Record<string,string>={consecutive_high_latency:'Два последовательных превышения порога',consecutive_healthy_latency:'Две последовательные здоровые проверки',observation_gap_or_clock_discontinuity:'Пропуск проверок или изменение часов',comparison_identity_changed:'Изменился профиль или адрес',noncomparable_or_missing_latency:'Нет сопоставимой задержки',baseline_expired:'Базовая линия устарела',monitor_paused_or_resumed:'Изменено состояние мониторинга',owner_toggle:'Действие владельца',migration_start_enabled:'Начало учёта после обновления',migration_start_paused:'Начало учёта после обновления, монитор на паузе',monitor_created_enabled:'Создан монитор',monitor_created_paused:'Создан приостановленный монитор'}
const stamp=(v:number|null)=>v===null?'—':new Date(v*1000).toLocaleString('ru-RU')
const ms=(v:number|null|undefined)=>v==null?'—':v.toFixed(1)+' мс'
const stateName=(s:string)=>states[s]??s
function pausedSpans(report:ObservatoryReport){
 const {since,before}=report.window
 const isPause=(b:ObservatoryBoundary)=>b.type==='monitor.paused'||(b.type==='tracking.started'&&b.reason.endsWith('_paused'))
 const prior=report.persistent.prior_boundary
 let from:number|null=prior&&isPause(prior)?since:null
 const spans:{from:number;to:number}[]=[]
 for(const b of [...report.persistent.journal].sort((a,b)=>a.at-b.at||a.seq-b.seq)){
  if(isPause(b)){if(from===null)from=b.at}
  else if(b.type==='monitor.resumed'||b.type==='tracking.started'){
   if(from!==null&&b.at>from)spans.push({from,to:b.at})
   from=null
  }
 }
 if(from!==null&&before>from)spans.push({from,to:before})
 return spans
}
function Chart({report,selected,onSelect}:{report:ObservatoryReport;selected:string;onSelect:(s:string)=>void}){
 const points=report.points
 const {since,before}=report.window
 const svgRef=useRef<SVGSVGElement>(null)
 const [width,setWidth]=useState(720)
 useEffect(()=>{
  const el=svgRef.current
  if(!el)return
  const resize=()=>setWidth(Math.max(240,Math.round(el.getBoundingClientRect().width)))
  resize()
  const observer=new ResizeObserver(resize)
  observer.observe(el)
  return ()=>observer.disconnect()
 },[])
 const height=width<480?230:250,left=width<480?34:48,right=12,top=18,bottom=36
 const max=Math.max(1,...points.flatMap(p=>[p.latency_ms??0,p.baseline_ms??0,p.threshold_ms??0]))*1.12
 const x=(t:number)=>left+Math.max(0,Math.min(1,(t-since)/(before-since)))*(width-left-right)
 const y=(n:number)=>top+(1-n/max)*(height-top-bottom)
 const spans=pausedSpans(report)
 const paths=(key:'latency_ms'|'baseline_ms'|'threshold_ms')=>{
  const parts:string[]=[];let last:ObservatoryPoint|undefined
  for(const p of points){
   const v=p[key]
   const broken=!last||p.gap_before||p.boundary_before||p.comparison_changed||last[key]===null||p.at<=last.at||
    spans.some(s=>last!==undefined&&s.from<p.at&&s.to>last.at)
   if(v!==null)parts.push((broken?'M':'L')+x(p.at).toFixed(2)+' '+y(v).toFixed(2))
   last=p
  }
  return parts.join(' ')
 }
 const chosen=points.find(p=>p.evidence_id===selected)
 return <><div className="obs-legend"><span><i className="obs-latency"/>Задержка</span><span><i className="obs-baseline"/>Базовая линия</span><span><i className="obs-threshold"/>Порог</span><span><i className="obs-pause"/>Пауза</span></div>
 <svg ref={svgRef} className="obs-chart" role="img" aria-label="График задержки, базовой линии и порога; разрывы обозначают отсутствие сопоставимых измерений" viewBox={'0 0 '+width+' '+height}>
  {Array.from({length:5},(_,i)=>{const v=max*i/4;return <g key={i}><line className="obs-gridline" x1={left} x2={width-right} y1={y(v)} y2={y(v)}/><text x={left-6} y={y(v)+4} textAnchor="end">{v.toFixed(max<10?1:0)}</text></g>})}
  {spans.map((s,i)=><rect className="obs-pause-band" key={i} x={x(s.from)} y={top} width={Math.max(0,x(s.to)-x(s.from))} height={height-top-bottom}/>)}
  <path data-series="baseline" d={paths('baseline_ms')} className="obs-line obs-line-baseline"/>
  <path data-series="threshold" d={paths('threshold_ms')} className="obs-line obs-line-threshold"/>
  <path data-series="latency" d={paths('latency_ms')} className="obs-line obs-line-latency"/>
  {points.filter(p=>p.latency_ms!==null).map(p=><circle key={p.evidence_id} cx={x(p.at)} cy={y(p.latency_ms!)} r={p.evidence_id===selected?5:2.4} className={'obs-dot '+(p.state==='anomaly'||p.state==='candidate'?'obs-dot-alert':'')}><title>{stamp(p.at)} · {ms(p.latency_ms)}</title></circle>)}
  {chosen&&<line x1={x(chosen.at)} x2={x(chosen.at)} y1={top} y2={height-bottom} className="obs-selection"/>}
  {(width<340?[0,1]:[0,.5,1]).map(f=><text key={f} x={x(since+(before-since)*f)} y={height-12} textAnchor={f===0?'start':f===1?'end':'middle'}>{new Date((since+(before-since)*f)*1000).toLocaleString('ru-RU',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'})}</text>)}
  <text x={left} y={12}>мс</text>
 </svg><small>Линии не соединяются через пропуски, смену профиля и известные паузы. Порог пересчитан в выбранном окне.</small>
 <label className="obs-point-picker">Измерение<select aria-label="Измерение" value={selected} onChange={e=>onSelect(e.target.value)}>{[...points].reverse().map(p=><option key={p.evidence_id} value={p.evidence_id}>{stamp(p.at)} · {ms(p.latency_ms)} · {stateName(p.state)}</option>)}</select></label></>
}
function Evidence({id}:{id:string}){
 const q=useQuery({queryKey:['obs-evidence',id],queryFn:({signal})=>api.intelligenceEvidence(id,signal),retry:false})
 return <div className="obs-evidence" aria-label="Данные наблюдения">{q.isPending?<p role="status">Загрузка…</p>:q.isError?<p role="alert">Наблюдение недоступно или удалено по политике хранения.</p>:<><small>{stamp(q.data.record.observed_at)} · {q.data.record.vantage_id}</small><dl className="intel-facts">{q.data.record.measurements.map(m=><div key={m.name}><dt>{m.name}</dt><dd>{m.value??'—'} {m.value===null?'':m.unit}</dd></div>)}</dl></>}</div>
}
function Detail({data}:{data:ObservatoryReport}){
 const [pointId,setPointId]=useState(''),[eventId,setEventId]=useState<number|null>(null),[evidence,setEvidence]=useState<string|null>(null)
 const p=data.points.find(p=>p.evidence_id===pointId)??data.points.at(-1)
 const current=data.persistent
 const live=!data.monitor.enabled?'paused':current.last_check_at===null?'learning':data.window.before-current.last_check_at>data.policy.gap_seconds?'stale':current.state_at_read
 const journal=[...current.journal].reverse()
 const selectedEvent=journal.find(e=>e.seq===eventId)
 return <><div className="stats obs-kpis">{[['Состояние',stateName(live)],['Здоровые проверки',data.observed_healthy_ratio===null?'—':(data.observed_healthy_ratio*100).toFixed(1)+'%'],['Наблюдения',data.counts.total],['Пропуски',data.gap_count]].map(([label,v])=><div className="panel metric" key={label}><span>{label}</span><strong>{v}</strong></div>)}</div>
 <section className="panel obs-status"><div className="obs-status-head"><span className={'obs-state state-'+live}>{stateName(live)}</span><span className="tag">{data.monitor.kind.toUpperCase()} · {data.monitor.interval_seconds} с</span></div><h2>{data.monitor.name}</h2><p>Текущее сохранённое состояние · последняя проверка {stamp(current.last_check_at)}</p><small>Базовая линия: {current.baseline_samples_at_read}/{data.policy.baseline_maximum} измерений · минимум {data.policy.baseline_minimum}</small><div className="intel-track"><span style={{width:Math.min(100,current.baseline_samples_at_read/data.policy.baseline_maximum*100)+'%'}}/></div></section>
 <div className="obs-layout"><section className="panel obs-chart-panel"><div className="section-title"><h2><Icon name="chart"/> Задержка и базовая линия</h2><span className="tag">Window analysis</span></div>{p?<><Chart report={data} selected={p.evidence_id} onSelect={id=>{setPointId(id);setEvidence(null)}}/><dl className="obs-point-facts"><div><dt>Задержка</dt><dd>{ms(p.latency_ms)}</dd></div><div><dt>Базовая линия</dt><dd>{ms(p.baseline_ms)}</dd></div><div><dt>Порог</dt><dd>{ms(p.threshold_ms)}</dd></div><div><dt>Состояние окна</dt><dd>{stateName(p.state)}</dd></div></dl><button className="secondary" onClick={()=>setEvidence(evidence===p.evidence_id?null:p.evidence_id)} aria-expanded={evidence===p.evidence_id}>Исходное измерение</button>{evidence===p.evidence_id&&<Evidence id={p.evidence_id}/>}</>:<div className="obs-empty"><Icon name="activity" size={36}/><h3>Нет наблюдений в периоде</h3><p>Дождитесь проверок мониторинга или выберите другой период.</p></div>}</section>
 <section className="panel obs-journal"><div className="section-title"><h2><Icon name="history"/> Журнал событий</h2><span className="tag">{journal.length}</span></div><small>Сохранённые события, не реконструкция графика.</small>{journal.length?<div className="obs-journal-list">{journal.map(e=><button className="obs-event secondary" key={e.seq} aria-pressed={eventId===e.seq} onClick={()=>{setEventId(e.seq);setEvidence(null)}}><i data-type={e.type}/><span><b>{events[e.type]??e.type}</b><small>{reasons[e.reason]??e.reason}</small><small>{stamp(e.at)}</small></span><Icon name="arrow" size={16}/></button>)}</div>:<p>В этом периоде нет сохранённых событий.</p>}{selectedEvent&&<div className="obs-event-detail"><h3>{events[selectedEvent.type]??selectedEvent.type}</h3><p>{reasons[selectedEvent.reason]??selectedEvent.reason}</p><dl className="intel-facts"><div><dt>Задержка</dt><dd>{ms(selectedEvent.latency_ms)}</dd></div><div><dt>Порог</dt><dd>{ms(selectedEvent.threshold_ms)}</dd></div></dl>{selectedEvent.evidence_id?<><button className="secondary" onClick={()=>setEvidence(evidence===selectedEvent.evidence_id?null:selectedEvent.evidence_id)} aria-expanded={evidence===selectedEvent.evidence_id}>Наблюдение события</button>{evidence===selectedEvent.evidence_id&&<Evidence id={selectedEvent.evidence_id}/>}</>:<small>Связанного измерения нет.</small>}</div>}</section></div>
 <section className="panel"><div className="section-title"><h2><Icon name="activity"/> Полнота и методика</h2></div><div className="obs-counts">{[['Успешно',data.counts.success],['Деградация',data.counts.degraded],['Сбои',data.counts.failure],['Неизвестно',data.counts.unknown]].map(([l,v])=><div key={l}><small>{l}</small><strong>{v}</strong></div>)}</div><p>Доля здоровых проверок не является непрерывным uptime. Неизвестные результаты исключены из знаменателя, пропуски не считаются сбоями.</p><p>Порог: медиана + максимум из 5 мс, 50% медианы и 6 × 1,4826 × MAD. Подтверждение: {data.policy.confirmation_checks} проверки; восстановление: {data.policy.recovery_checks}.</p><p>Покрытие не подтверждено. Учёт начат {stamp(current.tracking_since)}; прежние паузы могут быть неизвестны. График пересчитывается по сохранённым измерениям, сохранённые события не пересчитываются при смене периода.</p><small>Очередь: {data.coverage.producer_status_at_response.pending} · пропущено аналитических записей: {data.coverage.producer_status_at_response.dropped} · вытеснено: {data.coverage.retained_usage_at_read.evicted} (общие счётчики мониторинга).</small>{data.coverage.stream_error&&<p className="intel-warning">Ошибка обработки аналитики: {data.coverage.stream_error}</p>}</section></>
}
export function Observatory(){
 const [id,setId]=useState(''),[hours,setHours]=useState(6),[before,setBefore]=useState(()=>Date.now()/1000)
 const list=useQuery({queryKey:['observatory-monitors'],queryFn:({signal})=>api.observatoryMonitors(signal),retry:false,refetchOnWindowFocus:false})
 const selected=list.data?.find(m=>m.id===id)??list.data?.[0]
 const report=useQuery({queryKey:['observatory',selected?.id,hours,before],queryFn:({signal})=>api.observatory(selected!.id,before-hours*3600,before,signal),enabled:!!selected,retry:false,refetchOnWindowFocus:false})
 const refresh=()=>{setBefore(Date.now()/1000);void list.refetch()}
 return <><header className="page-heading"><div><div className="eyebrow">INTELLIGENCE / NETWORK HEALTH</div><h1>Network Observatory</h1><p>Наблюдение за сетью, адаптивные пороги и история аномалий.</p></div><button className="secondary" onClick={refresh} disabled={list.isFetching||report.isFetching}><Icon name="clock"/> Обновить</button></header>
 {list.isPending?<section className="panel" role="status">Загрузка мониторов…</section>:list.isError?<section className="panel" role="alert"><h2>Мониторы недоступны</h2><button className="secondary" onClick={()=>void list.refetch()}>Повторить</button></section>:!selected?<section className="panel obs-empty"><Icon name="activity" size={42}/><h2>Нет настроенных мониторов</h2><p>Добавьте монитор, чтобы Observatory мог изучать поведение сети.</p><Link className="primary-link" to="/monitoring">Настроить мониторинг</Link></section>:<>
 <section className="panel obs-controls"><label>Монитор<select aria-label="Монитор" value={selected.id} onChange={e=>{setId(e.target.value);setBefore(Date.now()/1000)}}>{list.data!.map(m=><option key={m.id} value={m.id}>{m.name} · {m.kind.toUpperCase()}{m.enabled?'':' · пауза'}</option>)}</select></label><label>Период<select aria-label="Период" value={hours} onChange={e=>{setHours(Number(e.target.value));setBefore(Date.now()/1000)}}><option value={1}>1 час</option><option value={6}>6 часов</option><option value={24}>24 часа</option><option value={72}>3 дня</option><option value={168}>7 дней</option></select></label><Link to="/monitoring">Управление мониторами <Icon name="arrow" size={16}/></Link></section>
 {report.isPending?<section className="panel" role="status">Загрузка анализа…</section>:report.isError?<section className="panel" role="alert"><h2>Анализ недоступен</h2><p>Выберите меньший период при превышении лимита 2000 наблюдений.</p><button className="secondary" onClick={()=>void report.refetch()}>Повторить</button></section>:report.data&&<Detail key={selected.id} data={report.data}/>}</>}</>
}
