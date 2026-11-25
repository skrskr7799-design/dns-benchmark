import {useState} from 'react'
import {useQuery} from '@tanstack/react-query'
import {api} from '../shared/api'
import {Results} from '../shared/results'
export function History(){
 const query=useQuery({queryKey:['history'],queryFn:api.history,refetchOnMount:'always'})
 const [selected,setSelected]=useState(0), runs=query.data??[], run=runs[selected]
 return <><header className="page-heading"><div><div className="eyebrow">WORKSPACE</div><h1>История</h1><p>Последние 30 сохранённых запусков.</p></div></header><section className="panel">{query.isPending?<p>Загрузка…</p>:query.isError?<p role="alert" className="error">{query.error.message}</p>:runs.length===0?<p className="empty">История пока пуста.</p>:<label>Запуск<select value={selected} onChange={e=>setSelected(Number(e.target.value))}>{runs.map((r,i)=><option value={i} key={i}>{new Date(r.time*1000).toLocaleString('ru-RU')} · {r.results.length} серверов</option>)}</select></label>}</section>{run&&<Results rows={run.results}/>}</>
}
