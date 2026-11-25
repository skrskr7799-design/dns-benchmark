import {useState} from 'react'
import {useQuery} from '@tanstack/react-query'
import {api} from '../shared/api'
import {Comparison,Samples} from '../shared/analytics'
import {Results} from '../shared/results'
export function History(){
 const query=useQuery({queryKey:['history'],queryFn:api.history,refetchOnMount:'always'})
 const [selected,setSelected]=useState(0), [baseline,setBaseline]=useState(-1), runs=query.data??[], run=runs[selected]
 return <><header className="page-heading"><div><div className="eyebrow">WORKSPACE</div><h1>История</h1><p>Последние 30 сохранённых запусков.</p></div></header><section className="panel">{query.isPending?<p>Загрузка…</p>:query.isError?<p role="alert" className="error">{query.error.message}</p>:runs.length===0?<p className="empty">История пока пуста.</p>:<label>Запуск<select value={selected} onChange={e=>setSelected(Number(e.target.value))}>{runs.map((r,i)=><option value={i} key={i}>{new Date(r.time*1000).toLocaleString('ru-RU')} · {r.results.length} серверов</option>)}</select></label>}{runs.length>1&&<label>Сравнить с запуском<select value={baseline} onChange={e=>setBaseline(Number(e.target.value))}><option value={-1}>Без сравнения</option>{runs.map((r,i)=><option key={i} value={i} disabled={i===selected}>{new Date(r.time*1000).toLocaleString('ru-RU')}</option>)}</select></label>}</section>{run&&<><Comparison rows={run.results} baseline={baseline!==selected?runs[baseline]?.results:undefined}/><Results key={selected} rows={run.results}/>{run.run_id&&<Samples key={run.run_id} runId={run.run_id}/>}</>}</>
}
