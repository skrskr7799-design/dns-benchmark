import {useMemo,useState} from 'react'
import {exportJson,type Result} from './api'
export const fmt = (v:number|null|undefined) => v == null ? '—' : v.toFixed(2)
export function Stats({rows}:{rows:Result[]}) {
  const count=rows.reduce((a,r)=>a+r.count,0), ok=rows.reduce((a,r)=>a+r.ok,0)
  const valid=rows.filter(r=>r.ok===r.count && r.p95!=null).map(r=>r.p95!)
  return <div className="stats"><div className="panel metric"><span>Проверено серверов</span><strong>{rows.length}</strong><small>{count} запросов</small></div><div className="panel metric"><span>Успешность</span><strong>{count?(100*ok/count).toFixed(1)+'%':'—'}</strong><small>{ok} успешных ответов</small></div><div className="panel metric"><span>Лучший P95</span><strong>{valid.length?fmt(Math.min(...valid))+' мс':'—'}</strong><small>Только без ошибок</small></div></div>
}
type Sort = 'reliability'|'mean'|'p95'|'jitter'
export function Results({rows}:{rows:Result[]}) {
  const [filter,setFilter]=useState(''), [sort,setSort]=useState<Sort>('reliability')
  const sorted=useMemo(()=>rows.filter(r=>r.endpoint.toLowerCase().includes(filter.toLowerCase())).sort((a,b)=>sort==='reliability'?b.ok/b.count-a.ok/a.count||(a.p95??Infinity)-(b.p95??Infinity):(a[sort]??Infinity)-(b[sort]??Infinity)),[rows,filter,sort])
  const top=sorted.filter(r=>r.ok===r.count&&r.mean!=null).slice().sort((a,b)=>a.mean!-b.mean!).slice(0,5)
  return <><Stats rows={rows}/>{top.length>0&&<section className="panel"><div className="section-title"><h2>Быстрые резолверы</h2><small>Средняя задержка · без ошибок</small></div>{top.map((r,i)=><div className="bar-row" key={i}><span title={r.endpoint}>{r.endpoint}</span><div className="track"><div style={{width:Math.max(2,100*r.mean!/Math.max(1,...top.map(x=>x.mean!)))+'%'}}/></div><b>{fmt(r.mean)} мс</b></div>)}</section>}
  <section className="panel"><div className="section-title"><h2>Результаты</h2><button className="secondary" disabled={!rows.length} onClick={()=>exportJson(rows)}>Экспорт JSON</button></div><div className="controls"><input aria-label="Поиск резолвера" placeholder="Поиск резолвера" value={filter} onChange={e=>setFilter(e.target.value)}/><select aria-label="Сортировка" value={sort} onChange={e=>setSort(e.target.value as Sort)}><option value="reliability">Надёжность / P95</option><option value="mean">Средняя задержка</option><option value="p95">P95</option><option value="jitter">Разброс задержек</option></select></div>
  {sorted.length===0?<p className="empty">Нет результатов для отображения.</p>:<div className="table-wrap"><table><thead><tr>{['Резолвер / IP','Режим','Успешно','Mean','P50','P95','P99','Разброс','Ошибка'].map(h=><th key={h}>{h}</th>)}</tr></thead><tbody>{sorted.map((r,i)=><tr key={i}><td><div className="endpoint">{r.endpoint}</div><small>{r.ip||'IP не сохранён'}</small></td><td>{r.mode||'—'}</td><td><span className={'status '+(r.ok===r.count?'ok':r.ok?'partial':'fail')}>{r.ok}/{r.count}</span></td>{[r.mean,r.p50,r.p95,r.p99,r.jitter].map((v,j)=><td key={j}>{fmt(v)}</td>)}<td>{r.error|| (r.ok<r.count?'Причина не записана':'—')}</td></tr>)}</tbody></table></div>}</section></>
}
