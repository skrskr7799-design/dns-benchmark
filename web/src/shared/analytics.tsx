import {useState} from 'react'
import {useQuery} from '@tanstack/react-query'
import {api,type Result} from './api'
import {fmt} from './results'

export function Comparison({rows,baseline}:{rows:Result[];baseline?:Result[]}){
 const pairs=baseline?rows.flatMap(r=>{const b=baseline.find(b=>b.endpoint===r.endpoint&&b.mode===r.mode);return b?[{a:b,b:r}]:[]}):rows.filter(r=>r.mode==='warm').flatMap(r=>{const c=rows.find(c=>c.endpoint===r.endpoint&&c.mode==='cold'&&c.ip===r.ip);return c?[{a:c,b:r}]:[]})
 if(!pairs.length)return null
 return <section className="panel"><h2>{baseline?'Сравнение запусков':'Cold / Warm · P95'}</h2><p>Сравниваются одинаковые адреса и режимы истории либо парные Cold/Warm. Различия IP, движка и ошибки влияют на сравнимость.</p><div className="table-wrap"><table><thead><tr><th>Резолвер</th><th>{baseline?'Базовый':'Cold'}</th><th>{baseline?'Текущий':'Warm'}</th><th>Δ P95</th><th>Успешно</th><th>Сопоставимость</th></tr></thead><tbody>{pairs.map(({a,b},i)=>{const same=a.ip!=null&&a.ip===b.ip&&a.engine!=null&&a.engine===b.engine&&a.family===b.family&&a.count===b.count;const valid=same&&a.count>0&&a.ok===a.count&&b.ok===b.count&&a.count===(a.requested_count??a.count)&&b.count===(b.requested_count??b.count)&&!b.warmup_error;return <tr key={i}><td>{b.endpoint}</td><td>{fmt(a.p95)}</td><td>{fmt(b.p95)}</td><td>{valid&&a.p95!=null&&b.p95!=null?fmt(b.p95-a.p95)+' мс':'—'}</td><td>{a.ok}/{a.count} → {b.ok}/{b.count}</td><td>{valid?'Сопоставимо по метаданным':'Ограничено'}</td></tr>})}</tbody></table></div></section>
}

export function Samples({runId,revision}:{runId:string;revision?:number}){
 const [offset,setOffset]=useState(0)
 const q=useQuery({queryKey:['samples',runId,offset,revision],queryFn:()=>api.samples(runId,offset)})
 const rows=q.data?.items??[]
 const max=Math.max(1,...rows.map(r=>r.duration_ms??0))
 return <section className="panel"><div className="section-title"><h2>Отдельные измерения</h2><div className="controls"><a href={'/api/v1/runs/'+encodeURIComponent(runId)+'/export?format=csv'} download>CSV</a><a href={'/api/v1/runs/'+encodeURIComponent(runId)+'/export?format=json'} download="dns-run.json">Полный JSON</a></div></div>
 {q.isError?<p role="alert" className="error">{q.error.message}</p>:q.isPending?<p>Загрузка…</p>:!q.data?.total?<p>Для этого запуска нет отдельных измерений.</p>:<><p>Задержки текущей страницы · красный — неуспешный запрос, пропуск — время не измерено.</p><div className="sample-chart" role="img" aria-label="График задержек отдельных запросов">{rows.map((r,i)=><div key={i} className={'sample-bar '+(r.ok?'':'sample-error')} title={r.domain+' · '+fmt(r.duration_ms)+' мс'} style={{height:r.duration_ms==null?'0%':Math.max(1,100*r.duration_ms/max)+'%'}}/>)}</div><div className="table-wrap"><table><thead><tr>{['Резолвер','Режим','Запрос','Задержка','TCP','Handshake','Протокол','Reuse','Ответ / ошибка'].map(x=><th key={x}>{x}</th>)}</tr></thead><tbody>{rows.map((r,i)=><tr key={i}><td>{r.endpoint}</td><td>{r.mode}</td><td>{r.domain}</td><td>{fmt(r.duration_ms)}</td><td>{fmt(r.connect_ms)}</td><td>{fmt(r.handshake_ms)}</td><td>{r.protocol??'—'}</td><td>{r.reused==null?'—':r.reused?'Да':'Нет'}</td><td>{r.error??r.rcode??'—'}</td></tr>)}</tbody></table></div></>}
 <div className="controls"><button className="secondary" disabled={!offset} onClick={()=>setOffset(Math.max(0,offset-200))}>Назад</button><small>{q.data?.total?offset+1:0}–{Math.min(offset+rows.length,q.data?.total??0)} / {q.data?.total??0}</small><button className="secondary" disabled={offset+200>=(q.data?.total??0)} onClick={()=>setOffset(offset+200)}>Далее</button></div></section>
}
