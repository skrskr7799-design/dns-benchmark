import {useEffect,useState} from 'react'
import {useMutation,useQuery,useQueryClient} from '@tanstack/react-query'
import {api,type Mode,type Family} from '../shared/api'
import {Comparison,Samples} from '../shared/analytics'
import {SamplePlots} from '../shared/plots'
import {Icon} from '../shared/identity'
import {Results,Stats} from '../shared/results'
export function useStatus(){return useQuery({queryKey:['status'],queryFn:api.status,refetchInterval:q=>q.state.data?.running?1000:3000})}
function saved():string|null{try{return localStorage.getItem('ndc.endpoints')}catch{return null}}
export function Benchmark(){
  const client=useQueryClient(), defaults=useQuery({queryKey:['defaults'],queryFn:api.defaults})
  const status=useStatus(), [endpoints,setEndpoints]=useState<string|null>(saved)
  const [count,setCount]=useState(10),[mode,setMode]=useState<Mode>('cold'),[family,setFamily]=useState<Family>('ipv4'),[parallel,setParallel]=useState(1)
  const value=endpoints??defaults.data?.join('\n')??''
  // Avoid an asynchronous default value replacing the DOM during the first edit.
  // Explicit manual mode takes ownership even if the defaults request is slow.
  const waitingDefaults=endpoints===null&&defaults.isPending
  const targets=value.split('\n').map(x=>x.trim()).filter(Boolean)
  useEffect(()=>{if(endpoints!==null)try{localStorage.setItem('ndc.endpoints',endpoints)}catch{/* storage optional */}},[endpoints])
  const start=useMutation({mutationFn:api.start,onSuccess:async()=>{await client.invalidateQueries({queryKey:['status']});await client.invalidateQueries({queryKey:['history']})}})
  const profiles=useQuery({queryKey:['profiles'],queryFn:api.profiles})
  const [profileName,setProfileName]=useState(''),[profileId,setProfileId]=useState('')
  const saveProfile=useMutation({mutationFn:()=>api.saveProfile(profileName.trim(),{endpoints:targets,count,mode,family,parallel}),onSuccess:p=>{setProfileId(p.id);setProfileName('');void client.invalidateQueries({queryKey:['profiles']})}})
  const removeProfile=useMutation({mutationFn:api.deleteProfile,onSuccess:()=>{setProfileId('');void client.invalidateQueries({queryKey:['profiles']})}})
  const runId=status.data?.running?status.data.run_id:undefined
  useEffect(()=>{if(!runId||typeof EventSource==='undefined')return;const stream=new EventSource('/api/v1/runs/'+encodeURIComponent(runId)+'/events');stream.addEventListener('snapshot',()=>{void client.invalidateQueries({queryKey:['status']})});stream.onerror=()=>stream.close();return()=>stream.close()},[runId,client])
  const cancel=useMutation({mutationFn:api.cancel,onSuccess:()=>client.invalidateQueries({queryKey:['status']})})
  const running=status.data?.running??false, disabled=running||start.isPending||!status.isSuccess||targets.length===0||targets.length>40||!Number.isInteger(count)||count<1||count>100
  return <><header className="page-heading"><div><div className="eyebrow">NETWORK TOOLS / DNS</div><h1>DNS Benchmark</h1><p>Сравнение резолверов из текущей точки сети.</p></div><span className="tag">Benchmark 2.0 · DNS-02</span></header>
  <section className="panel benchmark-config"><div className="section-title"><h2><Icon name="settings"/> Параметры тестирования</h2><button className="secondary" disabled={running||(!waitingDefaults&&!defaults.data)} onClick={()=>{if(waitingDefaults)setEndpoints('');else if(defaults.data)setEndpoints(defaults.data.join('\n'))}}>{waitingDefaults?'Ввести вручную':'Список по умолчанию'}</button></div>
  <div className="controls"><select aria-label="Сохранённый профиль" value={profileId} disabled={running} onChange={e=>{const id=e.target.value;setProfileId(id);const p=profiles.data?.find(x=>x.id===id);if(p){setEndpoints(p.config.endpoints.join('\n'));setCount(p.config.count);setMode(p.config.mode);setFamily(p.config.family);setParallel(p.config.parallel)}}}><option value="">Выбрать профиль</option>{profiles.data?.map(p=><option key={p.id} value={p.id}>{p.name}</option>)}</select><input aria-label="Название профиля" placeholder="Название нового профиля" value={profileName} maxLength={100} onChange={e=>setProfileName(e.target.value)}/><button className="secondary" disabled={disabled||!profileName.trim()||saveProfile.isPending} onClick={()=>saveProfile.mutate()}>Сохранить профиль</button><button className="secondary" disabled={!profileId||running||removeProfile.isPending} onClick={()=>removeProfile.mutate(profileId)}>Удалить профиль</button></div>{(profiles.isError||saveProfile.isError||removeProfile.isError)&&<p role="alert" className="error">{profiles.error?.message||saveProfile.error?.message||removeProfile.error?.message}</p>}<label htmlFor="endpoints">DNS-адреса · {targets.length}/40</label><textarea id="endpoints" value={value} onChange={e=>setEndpoints(e.target.value)} disabled={running} readOnly={waitingDefaults} placeholder={waitingDefaults?'Загрузка списка DNS…':undefined} rows={5} spellCheck={false}/>
  <div className="form-grid"><label>Запросов<input type="number" min={1} max={100} value={count} onChange={e=>setCount(Number(e.target.value))} disabled={running}/></label><label>Режим<select value={mode} onChange={e=>setMode(e.target.value as Mode)} disabled={running}><option value="cold">Cold</option><option value="warm">Warm</option><option value="both">Both · Cold + Warm</option></select></label><label>Сеть<select value={family} onChange={e=>setFamily(e.target.value as Family)} disabled={running}><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option><option value="auto">Auto</option></select></label><label>Потоки<select value={parallel} onChange={e=>setParallel(Number(e.target.value))} disabled={running}><option value={1}>1 · последовательно</option><option value={2}>2 · параллельно</option></select></label></div>
  <div className="controls"><button disabled={disabled} onClick={()=>start.mutate({endpoints:targets,count,mode,family,parallel})}>{running?'Тест выполняется…':start.isPending?'Запуск…':'Запустить тест'}</button>{running&&status.data?.run_id&&<button className="secondary" disabled={cancel.isPending||status.data.state==='cancelling'} onClick={()=>cancel.mutate(status.data!.run_id!)}>{status.data.state==='cancelling'?'Остановка…':'Остановить'}</button>}<small>HTTP/3 и DoQ: новый движок, проверка реальной сети ещё впереди.</small></div>
  {(status.isError||defaults.isError||start.isError||cancel.isError||status.data?.error)&&<p role="alert" className="error">{cancel.error?.message||start.error?.message||status.error?.message||defaults.error?.message||status.data?.error}</p>}
  {status.data&&status.data.total>0&&<div className="progress"><progress max={status.data.total} value={status.data.done}/><small role="status">{status.data.done} / {status.data.total} серий · {status.data.state??''}</small></div>}</section>
  <Stats rows={status.data?.results??[]}/>{status.data?.run_id&&<SamplePlots runId={status.data.run_id} revision={status.data.revision}/>}<Results key={status.data?.run_id??'none'} rows={status.data?.results??[]} showStats={false}/><Comparison rows={status.data?.results??[]}/>{status.data?.run_id&&<Samples key={status.data.run_id} runId={status.data.run_id} revision={status.data.revision}/>}</>
}
