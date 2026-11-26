import {useState} from 'react'
import {useQuery,useMutation,useQueryClient} from '@tanstack/react-query'
import {api,type ExperimentSummary,type ExperimentDetail} from '../shared/api'
export function SavedExperiments({kind,selected,setSelected,busy}:{kind:ExperimentSummary['kind'];selected:string;setSelected:(v:string)=>void;busy:boolean}){
 const qc=useQueryClient(),[confirm,setConfirm]=useState(false)
 const history=useQuery({queryKey:['experiments',kind],queryFn:({signal})=>api.experimentHistory(kind,signal)})
 const remove=useMutation({mutationFn:(id:string)=>api.experimentDelete(id),onSuccess:()=>{setSelected('');setConfirm(false);void qc.invalidateQueries({queryKey:['experiments',kind]})}})
 return <section className="panel"><h2>Saved experiments</h2><p>До 100 отчётов и 16 МиБ на оба модуля. Без автоматического удаления; экспортируйте нужные отчёты перед удалением.</p><label>Сохранённый отчёт<select aria-label="Сохранённый отчёт" value={selected} disabled={busy||remove.isPending} onChange={e=>{setSelected(e.target.value);setConfirm(false);remove.reset()}}><option value="">Текущий результат</option>{history.data?.map(r=><option key={r.id} value={r.id}>{new Date(r.created*1000).toLocaleString()} · {r.status} · {r.id.slice(0,8)}</option>)}</select></label>{history.isError&&<p className="error" role="alert">{history.error.message}</p>}{history.isSuccess&&!history.data.length&&<p>Сохранённых отчётов нет.</p>}{selected&&<><label className="global-check"><input type="checkbox" checked={confirm} disabled={busy||remove.isPending} onChange={e=>setConfirm(e.target.checked)}/>Подтверждаю удаление отчёта</label><button className="secondary" disabled={!confirm||busy||remove.isPending} onClick={()=>remove.mutate(selected)}>Удалить отчёт</button></>}{remove.isError&&<p role="alert" className="error">{remove.error.message}</p>}</section>
}
export function useSavedExperiment(kind:ExperimentSummary['kind'],id:string){
 return useQuery({queryKey:['experiment',kind,id],queryFn:async({signal}):Promise<ExperimentDetail>=>{const r=await api.experimentDetail(id,signal);if(r.kind!==kind)throw Error('Несовместимый отчёт');return r},enabled:!!id})
}
export function downloadExperiment(report:unknown,name:string){
 const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}))
 const a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)
}
