import {useId} from 'react'
import {useQuery} from '@tanstack/react-query'
import {api} from './api'
import {fmt} from './results'
import {Icon} from './identity'
export function LatencyPlot({values,label}:{values:(number|null)[];label:string}){
 const id=useId().replace(/:/g,'')
 const valid=values.filter((v):v is number=>v!==null&&Number.isFinite(v)&&v>=0),max=Math.max(1,...valid)
 if(!valid.length)return <p className="empty">Нет измеренных задержек.</p>
 const px=(i:number)=>44+i*500/Math.max(1,values.length-1),py=(v:number)=>158-v/max*132
 let d='',previous=false
 values.forEach((v,i)=>{if(v==null||!Number.isFinite(v)||v<0){previous=false;return}d+=(previous?' L':' M')+px(i)+' '+py(v);previous=true})
 return <svg viewBox="0 0 560 190" className="data-plot" role="img" aria-label={label}><defs><linearGradient id={id} x1="0" x2="0" y1="0" y2="1"><stop stopColor="#80D6DF" stopOpacity=".2"/><stop offset="1" stopColor="#80D6DF" stopOpacity="0"/></linearGradient></defs>{[0,.25,.5,.75,1].map(t=><g key={t}><line x1="44" x2="544" y1={py(max*t)} y2={py(max*t)} stroke="#293A44"/><text x="37" y={py(max*t)+4} textAnchor="end">{Number((max*t).toFixed(1))}</text></g>)}<text x="44" y="14">мс</text>{valid.length===values.length&&values.length>1&&<path d={d+' L544 158 L44 158 Z'} fill={'url(#'+id+')'}/>}<path d={d} fill="none" stroke="#80D6DF" strokeWidth="1.8" strokeLinejoin="round"/>{values.length<=40&&values.map((v,i)=>v==null?null:<circle key={i} cx={px(i)} cy={py(v)} r="2.8" fill="#80D6DF"><title>{i+1}: {fmt(v)} мс</title></circle>)}<text x="44" y="180">1</text><text x="544" y="180" textAnchor="end">{values.length}</text></svg>
}
export function SamplePlots({runId,revision}:{runId:string;revision?:number}){
 const q=useQuery({queryKey:['samples',runId,0,revision],queryFn:()=>api.samples(runId,0)})
 const rows=q.data?.items??[],values=rows.map(r=>r.ok?r.duration_ms:null),valid=values.filter((v):v is number=>v!==null&&Number.isFinite(v)&&v>=0)
 const max=Math.max(1,...valid),bins=Array.from({length:10},(_,i)=>({from:i*max/10,to:(i+1)*max/10,count:0}))
 for(const v of valid)bins[Math.min(9,Math.floor(v/max*10))].count++
 const peak=Math.max(1,...bins.map(b=>b.count))
 return <div className="plot-grid"><section className="panel"><h2><Icon name="activity"/> Response time</h2><p>Порядок записей, не временная шкала · первые {rows.length} из {q.data?.total??'—'} запросов.</p>{q.isPending?<p>Загрузка…</p>:q.isError?<p className="error">Данные недоступны.</p>:<LatencyPlot values={values} label="Задержка успешных запросов в порядке записей"/>}</section><section className="panel"><h2><Icon name="chart"/> Latency distribution</h2><p>Успешные запросы на той же странице · {valid.length} значений.</p>{valid.length?<div className="histogram" role="img" aria-label="Распределение задержек">{bins.map((b,i)=><div key={i} className="hist-bin"><span>{b.count||''}</span><div className="hist-fill" title={fmt(b.from)+'–'+fmt(b.to)+' мс: '+b.count} style={{height:(b.count/peak*100)+'%'}}/><small>{i%2===0?Number(b.from.toFixed(1)):''}</small></div>)}</div>:<p className="empty">Нет успешных измерений.</p>}<small>Диапазон: 0–{fmt(max)} мс · не статистика всего запуска.</small></section></div>
}
