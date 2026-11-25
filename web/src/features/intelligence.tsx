import {useState} from 'react'
import {useQuery} from '@tanstack/react-query'
import {Link} from '@tanstack/react-router'
import {api,type IntelligencePreset,type IntelligenceTarget,type IntelligenceRanking,type ScoreKey} from '../shared/api'
import {Icon} from '../shared/identity'

const presets=[['balanced','Баланс'],['reliability','Надёжность'],['speed','Скорость']] as const
const keys:ScoreKey[]=['reliability','p50','p95','jitter']
const labels:Record<ScoreKey,string>={reliability:'Успешность',p50:'P50',p95:'P95',jitter:'Jitter'}
const reasonLabels:Record<string,string>={
 insufficient_matched_runs:'Недостаточно сопоставимых запусков',insufficient_attempts:'Недостаточно запросов',
 insufficient_successful_queries:'Недостаточно успешных запросов',incomplete_latency_coverage:'Неполные данные задержек',
 missing_latency:'Нет данных задержек',producer_backlog_or_error:'Очередь обработки или ошибка источника',
 fewer_than_two_scored_targets:'Менее двух оценённых DNS',best_target_below_reliability_floor:'Лучший результат ниже порога успешности',
 tied_top_score:'Одинаковый лучший балл',missing_or_noncompleted_source_run:'Исходный запуск отсутствует или не завершён',
 fewer_than_two_same_protocol_targets:'Менее двух DNS одного протокола',unmatched_or_duplicate_target_set:'Неполный или повторяющийся набор DNS',
 ineligible_or_mismatched_series:'Несопоставимые или неполные серии',duplicate_target_identity:'Повторяющийся идентификатор DNS',
 local_controller_only:'Только измерения локального контроллера',same_protocol_family_workload_and_target_set:'Одинаковый протокол, семейство IP, профиль и набор DNS',
 conditional_on_retained_matched_runs:'Рейтинг только по сохранённым сопоставимым тестам',
 excluded_runs_may_bias_scores:'Исключённые тесты могут влиять на оценку',
 series_percentiles_not_pooled_percentiles:'Медианы перцентилей серий, не общие перцентили',
 reference_budgets_are_policy_not_standards:'Опорные задержки — настройки методики, не стандарты',
 observed_success_not_continuous_availability:'Успешность запросов не равна непрерывной доступности',
 same_ip_not_same_physical_anycast_node:'Одинаковый IP не гарантирует одинаковый anycast-узел',
 no_privacy_security_or_filtering_score:'Приватность, фильтрация и безопасность не оцениваются',
 no_automatic_dns_configuration:'Настройки DNS не меняются автоматически',
 no_failover_independence_claim:'Независимость резервного DNS не проверяется',
 result_commit_time:'Время сохранения результата',peer_ip_unverified:'IP фактического собеседника не подтверждён',
 anycast_identity_unverified:'Физический anycast-узел не подтверждён',protocol_unverified_or_mixed:'Протокол не подтверждён или смешанный',
 bootstrap_ip_unavailable:'IP резолвера не определён',sample_coverage_unverified:'Полнота образцов не подтверждена',
 warmup_unverified_or_failed:'Прогрев не подтверждён или неуспешен',incomplete_source_metadata:'Неполные метаданные источника'
}
const reason=(k:string)=>reasonLabels[k]??k
const fmt=(v:number|null,digits=2)=>v===null?'—':v.toFixed(digits)
const date=(v:number)=>new Date(v*1000).toLocaleString('ru-RU')
function Evidence({id}:{id:string}){
 const q=useQuery({queryKey:['intelligence-evidence',id],queryFn:({signal})=>api.intelligenceEvidence(id,signal),retry:false})
 return <section className="intel-evidence" aria-label="Исходное наблюдение">{q.isPending?<p role="status">Загрузка наблюдения…</p>:q.isError?<p role="alert" className="error">Наблюдение недоступно или срок хранения истёк. <button className="secondary" onClick={()=>void q.refetch()}>Повторить</button></p>:<><h3>Исходное наблюдение</h3><p><small>{date(q.data.received_at)} · {q.data.record.vantage_id} · {q.data.record.outcome}</small></p><p className="intel-mono">{q.data.record.run_id??q.data.record.source_id}</p><dl className="intel-facts">{q.data.record.measurements.map(m=><div key={m.name}><dt>{m.name}</dt><dd>{fmt(m.value)} {m.value!==null?m.unit:''}</dd></div>)}</dl>{q.data.record.limitations.map(x=><p key={x}><small>{reason(x)}</small></p>)}</>}</section>
}
function ScoreDetails({target,data}:{target:IntelligenceTarget;data:IntelligenceRanking}){
 const [open,setOpen]=useState(false)
 return <section className="panel intel-details"><div className="section-title"><h2><Icon name="intelligence"/> Разбор оценки</h2><span className="tag">Score / 100</span></div>
 <div className="intel-detail-target"><strong>{target.endpoint}</strong><small>{target.bootstrap_ip}</small></div>
 {target.components?<><div className="intel-detail-score"><strong>{fmt(target.score)}</strong><small>из 100 баллов</small></div>{keys.map(k=>{const c=target.components![k];return <div className="intel-contribution" key={k}><div><b>{labels[k]}</b><small>{fmt(c.contribution)} / {c.weight}</small></div><div className="intel-track"><span data-metric={k} style={{width:c.weight?Math.min(100,c.contribution/c.weight*100)+'%':'0%'}}/></div><small>Нормированная оценка {fmt(c.normalized)} / 100</small></div>})}</>:<div className="intel-notice"><b>Оценка недоступна</b>{target.unranked_reasons.map(x=><p key={x}>{reason(x)}</p>)}</div>}
 <dl className="intel-facts"><div><dt>Запросы</dt><dd>{target.successful} / {target.attempted}</dd></div><div><dt>Серии с задержками</dt><dd>{target.latency_series} / {target.successful_series}</dd></div></dl>
 <p><small>Опорные задержки: P50 {data.latency_reference_ms.p50}, P95 {data.latency_reference_ms.p95}, jitter {data.latency_reference_ms.jitter} мс.</small></p>
 <button className="secondary intel-evidence-toggle" aria-expanded={open} onClick={()=>setOpen(v=>!v)}>{open?'Скрыть наблюдение':'Исходное наблюдение'} <Icon name="arrow" size={16}/></button>
 {open&&<Evidence id={target.example_evidence_id}/>}</section>
}
export function DNSIntelligence(){
 const [days,setDays]=useState(7),[preset,setPreset]=useState<IntelligencePreset>('balanced')
 const [before,setBefore]=useState(()=>Date.now()/1000),[groupId,setGroupId]=useState(''),[targetId,setTargetId]=useState('')
 const [mode,setMode]=useState('all'),[family,setFamily]=useState('all'),[protocol,setProtocol]=useState('all')
 const q=useQuery({queryKey:['intelligence',days,before,preset],queryFn:({signal})=>api.intelligence(before-days*86400,before,preset,signal),retry:false,refetchOnWindowFocus:false})
 const data=q.data
 const groups=(data?.groups??[]).filter(g=>(mode==='all'||g.mode===mode)&&(family==='all'||g.family===family)&&(protocol==='all'||g.protocol===protocol))
 const group=groups.find(g=>g.group_id===groupId)??groups[0]
 const target=group?.targets.find(t=>t.target_id===targetId)??group?.targets.find(t=>t.target_id===group.recommended_target_id)??group?.targets[0]
 const recommended=group?.targets.find(t=>t.target_id===group.recommended_target_id)
 const protocols=Array.from(new Set((data?.groups??[]).map(g=>g.protocol))).sort()
 const refresh=()=>{setBefore(Date.now()/1000)}
 return <><header className="page-heading"><div><div className="eyebrow">INTELLIGENCE / DNS ANALYSIS</div><h1>DNS Intelligence</h1><p>Сопоставимые измерения. Объяснимый рейтинг. Обоснованный выбор DNS.</p></div><button className="secondary" onClick={refresh} disabled={q.isFetching}><Icon name="clock"/> Обновить анализ</button></header>
 <section className="panel intel-controls"><div className="section-title"><h2><Icon name="settings"/> Параметры анализа</h2><span className="tag">Local controller</span></div>
 <div className="intel-filters"><label>Период<select value={days} onChange={e=>{setDays(Number(e.target.value));refresh()}}><option value={1}>24 часа</option><option value={7}>7 дней</option><option value={30}>30 дней</option></select></label><label>Режим<select value={mode} onChange={e=>setMode(e.target.value)}><option value="all">Все режимы</option><option value="cold">Cold</option><option value="warm">Warm</option></select></label><label>Семейство IP<select value={family} onChange={e=>setFamily(e.target.value)}><option value="all">Все</option><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select></label><label>Протокол<select value={protocol} onChange={e=>setProtocol(e.target.value)}><option value="all">Все протоколы</option>{Array.from(new Set([...protocols,...(protocol==='all'?[]:[protocol])])).map(p=><option key={p} value={p}>{p.toUpperCase()}</option>)}</select></label></div>
 <div className="intel-priority"><small>Приоритет оценки</small><div className="view-tabs" role="group" aria-label="Приоритет оценки">{presets.map(([key,label])=><button key={key} className="secondary" aria-pressed={preset===key} onClick={()=>setPreset(key)}>{label}</button>)}</div></div>
 {data&&<><div className="intel-weight-track" aria-label="Веса параметров">{keys.map(k=><span key={k} data-metric={k} style={{width:data.weights[k]+'%'}}/>)}</div><div className="intel-legend">{keys.map(k=><span key={k}><i data-metric={k}/>{labels[k]} <b>{data.weights[k]}%</b></span>)}</div></>}
 </section>
 {q.isPending?<section className="panel tool-ready" role="status"><div className="activity-ring"/><div><h2>Анализ измерений</h2><p>Загрузка сохранённых результатов…</p></div></section>:q.isError?<section className="panel" role="alert"><h2>Анализ недоступен</h2><p className="error">Не удалось получить рейтинг. При слишком большом объёме данных выберите меньший период.</p><button className="secondary" onClick={()=>void q.refetch()}>Повторить</button></section>:data&&<>
 <div className="stats intel-kpis">{[['Наблюдения',data.records_read],['Запуски',data.runs_considered],['Группы сравнения',data.groups.length],['В очереди',data.coverage.producer_pending]].map(([label,n])=><div key={label} className="panel metric"><span>{label}</span><strong>{n}</strong></div>)}</div>
 <section className="panel intel-coverage"><div><Icon name="activity"/><div><b>Покрытие измерений не подтверждено</b><p>Анализ ограничен сохранёнными сопоставимыми сериями. Успешность запросов не равна uptime.</p></div></div><small>{date(data.coverage.since)} — {date(data.coverage.before)} · время поступления</small>{(data.coverage.producer_pending>0||data.coverage.stream_error)&&<p className="intel-warning" role="status">Есть очередь или ошибка обработки. Рекомендации временно недоступны.</p>}</section>
 {!group?<section className="panel intel-empty"><Icon name="intelligence" size={44}/><h2>{data.groups.length?'Нет групп по выбранным фильтрам':'Недостаточно сопоставимых данных'}</h2><p>{data.groups.length?'Измените режим, протокол или семейство IP.':'Запустите одинаковый DNS Benchmark не менее '+data.minimum.matched_runs+' раз: два или более DNS одного протокола, одинаковый режим и настройки. Для оценки нужно от '+data.minimum.attempted_queries+' запросов на DNS.'}</p><Link className="primary-link" to="/benchmark">Открыть DNS Benchmark</Link></section>:<>
 <section className="panel intel-group"><label>Группа сравнения<select value={group.group_id} onChange={e=>{setGroupId(e.target.value);setTargetId('')}}>{groups.map((g,i)=><option key={g.group_id} value={g.group_id}>{i+1} · {g.mode.toUpperCase()} / {g.protocol.toUpperCase()} / {g.family.toUpperCase()} · {g.targets.length} DNS · {g.matched_runs} тестов · {g.profile_revision.slice(0,8)}</option>)}</select></label><small>Один набор DNS и профиль · {group.matched_runs} сопоставимых запусков · {date(group.first_received_at)} — {date(group.last_received_at)}</small></section>
 <section className="panel intel-recommendation"><div className="intel-recommend-mark"><Icon name={recommended?'check':'intelligence'} size={26}/></div><div><div className="eyebrow">{recommended?'CONDITIONAL RECOMMENDATION':'RECOMMENDATION WITHHELD'}</div><h2>{recommended?'Рекомендуемый DNS':'Нет однозначной рекомендации'}</h2>{recommended?<><strong className="intel-endpoint">{recommended.endpoint}</strong><p>Лучший балл среди оценённых DNS · {fmt(recommended.observed_success_ratio*100)}% успешных запросов. Только в выбранной группе.</p></>:<p>{group.recommendation_blockers.map(reason).join(' · ')||'Недостаточно подтверждённых данных.'}</p>}</div>{recommended&&<strong className="intel-recommend-score">{fmt(recommended.score)}</strong>}</section>
 <div className="intel-layout"><section className="panel intel-ranking"><div className="section-title"><h2><Icon name="chart"/> Рейтинг DNS</h2><span className="tag">{group.protocol.toUpperCase()} · {group.family.toUpperCase()}</span></div><p><small>Выберите DNS для разбора оценки. P50, P95 и jitter — медианы по сериям.</small></p><div className="intel-list">{group.targets.map(t=><button key={t.target_id} className="intel-row" aria-pressed={target?.target_id===t.target_id} aria-label={'Разбор '+t.endpoint} onClick={()=>setTargetId(t.target_id)}><span className="intel-rank">{t.rank===null?'—':String(t.rank).padStart(2,'0')}</span><span className="intel-row-main"><b className="intel-endpoint">{t.endpoint}</b><small>{t.bootstrap_ip} · {t.successful}/{t.attempted} запросов</small><span className="intel-track"><span style={{width:(t.score??0)+'%'}}/></span><span className="intel-row-metrics"><span>P50 <b>{fmt(t.median_series_ms.p50,1)}</b></span><span>P95 <b>{fmt(t.median_series_ms.p95,1)}</b></span><span>Jitter <b>{fmt(t.median_series_ms.jitter,1)}</b></span></span></span><span className="intel-row-score"><strong>{fmt(t.score)}</strong><small>{t.score===null?'Нет оценки':'/ 100'}</small></span></button>)}</div></section>{target&&<ScoreDetails key={group.group_id+target.target_id} target={target} data={data}/>}</div></>}
 <section className="panel intel-method"><h2><Icon name="search"/> Методика и исключения</h2><p>Минимум {data.minimum.matched_runs} запусков, {data.minimum.attempted_queries} запросов, {data.minimum.successful_queries} успешных запросов на DNS. Порог рекомендации — {data.minimum.recommendation_success_ratio*100}%.</p><details><summary>Исключённые группы тестов</summary>{Object.entries(data.excluded_run_groups).length?<dl className="intel-facts">{Object.entries(data.excluded_run_groups).map(([k,v])=><div key={k}><dt>{reason(k)}</dt><dd>{v}</dd></div>)}</dl>:<p>Нет зарегистрированных исключений в выбранном окне.</p>}</details><details><summary>Ограничения методики · {data.methodology}</summary>{data.limitations.map(x=><p key={x}><small>{reason(x)}</small></p>)}</details></section>
 </>}</>
}
