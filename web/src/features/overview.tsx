import {useQuery} from '@tanstack/react-query'
import {Link} from '@tanstack/react-router'
import {useStatus} from './benchmark'
import {api,type Result} from '../shared/api'
import {fmt} from '../shared/results'
import {Icon} from '../shared/identity'
function label(endpoint:string){try{return new URL(endpoint).hostname}catch{return endpoint}}
function full(r:Result){return r.count>0&&r.ok===r.count&&r.count===(r.requested_count??r.count)&&!r.warmup_error}
export function Overview(){
 const status=useStatus(),history=useQuery({queryKey:['history'],queryFn:api.history}),monitor=useQuery({queryKey:['monitoring'],queryFn:api.monitoring,refetchInterval:10000}),agents=useQuery({queryKey:['agents'],queryFn:api.agents,refetchInterval:10000})
 const rows=status.data?.results.length?status.data.results:history.data?.[0]?.results??[]
 const total=rows.reduce((a,r)=>a+r.count,0),ok=rows.reduce((a,r)=>a+r.ok,0)
 const best=rows.filter(r=>full(r)&&r.mean!=null).slice().sort((a,b)=>a.mean!-b.mean!).slice(0,5)
 const base=best[0],mon=monitor.data?.monitors??[],nodes=agents.data?.agents??[]
 const recent=(history.data??[]).slice(0,5)
 return <><header className="page-heading"><div><div className="eyebrow">WORKSPACE / OVERVIEW</div><h1>Network overview</h1><p>Производительность DNS, состояние сервисов и диагностика.</p></div><Link className="primary-link" to="/benchmark"><Icon name="play"/> Новый тест</Link></header>
 <div className="overview-kpis">
 <section className="panel metric"><span><Icon name="activity"/> Controller</span><strong>{status.isError?'Недоступен':status.isPending?'—':'Online'}</strong><small>{status.data?.running?'Тест выполняется':'Локальная точка измерения'}</small></section>
 <section className="panel metric"><span><Icon name="benchmark"/> Best DNS response</span><strong className="accent">{fmt(base?.mean)} <small>мс</small></strong><small>{base?label(base.endpoint)+' · '+(base.mode??'—'):'Нет измерений'}</small></section>
 <section className="panel metric"><span><Icon name="check"/> DNS success</span><strong>{total?(100*ok/total).toFixed(1)+'%':'—'}</strong><small>{ok} / {total} измеренных запросов</small></section>
 <section className="panel metric"><span><Icon name="agents"/> Agents online</span><strong>{agents.isSuccess?nodes.filter(a=>a.online).length+' / '+nodes.length:'—'}</strong><small>Последние heartbeat</small></section></div>
 <div className="overview-grid">
 <section className="panel overview-ranking"><div className="section-title"><h2><Icon name="chart"/> DNS Benchmark</h2><Link to="/benchmark">Подробнее <Icon name="arrow" size={15}/></Link></div><p>Лучшие полные успешные серии · средняя задержка.</p>{best.length?<div className="table-wrap"><table><thead><tr><th>Резолвер</th><th>Режим</th><th>Mean</th><th>P95</th><th>Успешно</th></tr></thead><tbody>{best.map((r,i)=><tr key={i}><td><b>{label(r.endpoint)}</b><small className="cell-note">{r.ip??r.endpoint}</small></td><td>{r.mode??'—'}</td><td className="accent">{fmt(r.mean)} мс</td><td>{fmt(r.p95)}</td><td>{r.ok}/{r.count}</td></tr>)}</tbody></table></div>:<p className="empty">Нет завершённых успешных серий. Запустите бенчмарк.</p>}</section>
 <section className="panel"><div className="section-title"><h2><Icon name="activity"/> Monitoring</h2><Link to="/monitoring">Открыть <Icon name="arrow" size={15}/></Link></div>{monitor.isError?<p className="error">Мониторинг недоступен</p>:!mon.length?<p className="empty">Мониторы не настроены.</p>:mon.slice(0,5).map(m=><div className="history-row" key={m.id}><span>{m.config.name}</span><small className={m.state==='incident'?'error':m.state==='healthy'&&m.enabled?'positive':''}>{!m.enabled?'Пауза':m.state} · {fmt(m.last_result?.latency_ms)} мс</small></div>)}</section>
 <section className="panel"><div className="section-title"><h2><Icon name="route"/> Route Analyzer</h2><Link to="/routes">Открыть <Icon name="arrow" size={15}/></Link></div><p>Маршрут до выбранной цели, промежуточные ответы и RTT.</p><div className="tool-empty"><Icon name="route" size={36}/><span>Маршруты измеряются по запросу</span></div></section>
 <section className="panel"><div className="section-title"><h2><Icon name="search"/> DNS Inspector</h2><Link to="/inspector">Открыть <Icon name="arrow" size={15}/></Link></div><p>Проверка DNS-записей, ответов и метаданных резолвера.</p><div className="tool-empty"><Icon name="dns" size={32}/><span>Выберите домен и тип записи</span></div></section>
 <section className="panel"><div className="section-title"><h2><Icon name="history"/> Последние запуски</h2><Link to="/history">Вся история</Link></div>{history.isError?<p role="alert">Не удалось загрузить историю</p>:history.isPending?<p>Загрузка…</p>:recent.length?recent.map((r,i)=><div className="history-row" key={i}><span>{new Date(r.time*1000).toLocaleString('ru-RU')}</span><small>{r.results.length} серий</small></div>):<p className="empty">Нет сохранённых запусков.</p>}</section>
 <section className="panel"><h2><Icon name="chart"/> Advanced analytics</h2>{base?<><p className="dns-value">{base.endpoint} · {base.mode??'—'}</p><div className="phase-grid">{[['P50',base.p50],['P95',base.p95],['P99',base.p99]].map(([n,v])=><div key={String(n)}><small>{n}</small><b>{fmt(v as number|null)} мс</b></div>)}</div><small>Разброс: {fmt(base.jitter)} мс</small></>:<p className="empty">Перцентили появятся после измерений.</p>}</section>
 </div><p className="muted overview-footnote">Данные текущего или последнего сохранённого теста. Не непрерывный мониторинг качества всей сети.</p></>
}
