import {useState,useRef} from 'react'
import {useMutation,useQuery} from '@tanstack/react-query'
import {api,type AgentNode,type GlobalMatrix,type GlobalRemoteKind,type GlobalPeerPlan,type GlobalRemoteRequest} from '../shared/api'
import {Icon} from '../shared/identity'
const requestId=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('')
const pin=/^[a-f0-9]{64}$/
type Pending<T>={signature:string;body:T}
function reuse<T extends {request_id:string}>(ref:{current:Pending<T>|null},signature:string,build:()=>T):T{
 if(ref.current?.signature!==signature)ref.current={signature,body:build()}
 return ref.current!.body
}
export function GlobalLaunch({nodes,coverage,onPeer,onBatch}:{nodes:AgentNode[];coverage?:GlobalMatrix['coverage'];onPeer:(kind:'rtt'|'goodput',id:string)=>void;onBatch:(id:string)=>void}){
 const [kind,setKind]=useState<'rtt'|'goodput'>('rtt'),[source,setSource]=useState(''),[destination,setDestination]=useState(''),[sourceIP,setSourceIP]=useState(''),[destinationIP,setDestinationIP]=useState(''),[sourcePin,setSourcePin]=useState(''),[destinationPin,setDestinationPin]=useState(''),[port,setPort]=useState(8443),[samples,setSamples]=useState(3),[bytes,setBytes]=useState(65536),[rate,setRate]=useState(1000000),[approved,setApproved]=useState(false)
 const [remote,setRemote]=useState<GlobalRemoteKind>('tcp'),[host,setHost]=useState(''),[remotePort,setRemotePort]=useState(443),[family,setFamily]=useState<'ipv4'|'ipv6'>('ipv4'),[scheme,setScheme]=useState<'http'|'https'>('https'),[path,setPath]=useState('/'),[hops,setHops]=useState(8),[selected,setSelected]=useState<string[]>([]),[remoteApproved,setRemoteApproved]=useState(false)
 const peerPending=useRef<Pending<GlobalPeerPlan>|null>(null),batchPending=useRef<Pending<GlobalRemoteRequest>|null>(null)
 const peers=nodes.filter(n=>n.enrolled&&!n.revoked)
 const caps=useQuery({queryKey:['global-capabilities'],queryFn:({signal})=>api.globalCapabilities(signal),refetchInterval:10000})
 const eligible=caps.isSuccess?peers.filter(n=>caps.data.agents.some(c=>c.id===n.id&&c.fresh&&c.dispatchable.includes(remote))):[]
 const chosen=selected.filter(id=>eligible.some(n=>n.id===id)).sort()
 const direction={source_agent_id:source,destination_agent_id:destination,source_ip:sourceIP.trim(),destination_ip:destinationIP.trim(),port,source_certificate:sourcePin.trim(),destination_certificate:destinationPin.trim()}
 const peerBody=kind==='rtt'?{direction,samples}:{policy:{direction,byte_count:bytes,rate_bps:rate}}
 const peerSignature=JSON.stringify([kind,peerBody]),remoteConfig={kind:remote,host:host.trim(),port:remote==='route'?33434:remotePort,family,...(remote==='http'?{scheme,path}:remote==='route'?{max_hops:hops}:{})}
 const batchSignature=JSON.stringify([chosen,remoteConfig])
 const peer=useMutation({mutationFn:()=>api.launchGlobalPeer(kind,reuse(peerPending,peerSignature,()=>({request_id:requestId(),...peerBody}))),onSuccess:r=>{peerPending.current=null;setApproved(false);onPeer(kind,r.id)}})
 const batch=useMutation({mutationFn:()=>api.launchGlobalBatch(reuse(batchPending,batchSignature,()=>({request_id:requestId(),agent_ids:chosen,config:remoteConfig}))),onSuccess:r=>{batchPending.current=null;setRemoteApproved(false);onBatch(r.id)}})
 const validPeer=!!coverage?.[kind].enabled&&approved&&source!==destination&&peers.some(n=>n.id===source)&&peers.some(n=>n.id===destination)&&!!sourceIP.trim()&&!!destinationIP.trim()&&pin.test(direction.source_certificate)&&pin.test(direction.destination_certificate)&&direction.source_certificate!==direction.destination_certificate&&Number.isInteger(port)&&port>=1024&&port<=65535&&(kind==='rtt'?Number.isInteger(samples)&&samples>=1&&samples<=5:Number.isInteger(bytes)&&bytes>=65536&&bytes<=4194304&&bytes%16384===0&&Number.isInteger(rate)&&rate>=256000&&rate<=8000000&&bytes*8<=rate*6)
 const validBatch=remoteApproved&&chosen.length>=2&&chosen.length<=8&&!!host.trim()&&(remote==='route'?Number.isInteger(hops)&&hops>=1&&hops<=8:Number.isInteger(remotePort)&&remotePort>=1&&remotePort<=65535)&&(remote!=='http'||(path.startsWith('/')&&!path.startsWith('//')&&!/[\\?#]/.test(path)))
 return <section className="panel global-panel global-launch"><h2><Icon name="benchmark"/> Запуск измерений</h2>
 <details><summary>Прямое измерение RTT / Throughput</summary><p>Только для направления и параметров, заранее разрешённых на обоих агентах. Введите IP и SHA-256 отпечатки публичных сертификатов из локальной конфигурации. Сервер и агент повторно проверят разрешения.</p>
 <form onSubmit={e=>{e.preventDefault();if(validPeer&&!peer.isPending)peer.mutate()}} onChange={()=>setApproved(false)}>
 <fieldset disabled={peer.isPending} className="global-fields"><label>Тип<select aria-label="Тип прямого измерения" value={kind} onChange={e=>setKind(e.target.value as 'rtt'|'goodput')}><option value="rtt">RTT</option><option value="goodput">Throughput</option></select></label>
 <label>Порт получателя<input type="number" min={1024} max={65535} value={port} onChange={e=>setPort(Number(e.target.value))}/></label>
 <label>Источник<select aria-label="Источник" value={source} onChange={e=>setSource(e.target.value)}><option value="">Выбрать</option>{peers.map(n=><option key={n.id} value={n.id}>{n.name}</option>)}</select></label>
 <label>Получатель<select aria-label="Получатель" value={destination} onChange={e=>setDestination(e.target.value)}><option value="">Выбрать</option>{peers.map(n=><option key={n.id} value={n.id}>{n.name}</option>)}</select></label>
 <label>IP источника<input required maxLength={64} value={sourceIP} onChange={e=>setSourceIP(e.target.value)}/></label><label>IP получателя<input required maxLength={64} value={destinationIP} onChange={e=>setDestinationIP(e.target.value)}/></label>
 <label>SHA-256 источника<input required maxLength={64} spellCheck={false} value={sourcePin} onChange={e=>setSourcePin(e.target.value)}/></label><label>SHA-256 получателя<input required maxLength={64} spellCheck={false} value={destinationPin} onChange={e=>setDestinationPin(e.target.value)}/></label>
 {kind==='rtt'?<label>Число эхо<input type="number" min={1} max={5} value={samples} onChange={e=>setSamples(Number(e.target.value))}/></label>:<><label>Байт<input type="number" min={65536} max={4194304} step={16384} value={bytes} onChange={e=>setBytes(Number(e.target.value))}/></label><label>Нагрузка, бит/с<input type="number" min={256000} max={8000000} value={rate} onChange={e=>setRate(Number(e.target.value))}/></label></>}
 </fieldset>
 <p className="muted">{coverage?.[kind].enabled?'Контроллер включён. Локальное разрешение и бюджет обязательны.':'Измерения этого типа отключены или состояние неизвестно.'}</p>
 <label className="global-check"><input type="checkbox" checked={approved} disabled={peer.isPending} onChange={e=>{e.stopPropagation();setApproved(e.target.checked)}}/>Подтверждаю точную локальную политику обоих агентов</label>
 <button disabled={!validPeer||peer.isPending}>Запустить прямое измерение</button>
 {peer.isError&&<p className="error" role="alert">{peer.error.message}</p>}{peer.isSuccess&&<p role="status">Запрос принят: {peer.data.id}</p>}
 </form></details>
 <details><summary>Удалённое сравнение TCP / TLS / HTTP / Route</summary><p>До 8 агентов со свежей поддержкой выбранного протокола. Цель и профиль должны быть разрешены локально на каждом агенте.</p>
 <form onSubmit={e=>{e.preventDefault();if(validBatch&&!batch.isPending)batch.mutate()}} onChange={()=>setRemoteApproved(false)}>
 <fieldset className="global-fields" disabled={batch.isPending}><label>Протокол<select aria-label="Протокол" value={remote} onChange={e=>{setRemote(e.target.value as GlobalRemoteKind);setSelected([])}}>{['tcp','tls','http','route'].map(k=><option key={k} value={k}>{k.toUpperCase()}</option>)}</select></label>
 <label>Целевой хост<input required maxLength={253} value={host} onChange={e=>setHost(e.target.value)}/></label><label>Семейство IP<select aria-label="Семейство IP" value={family} onChange={e=>setFamily(e.target.value as 'ipv4'|'ipv6')}><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select></label>
 {remote==='route'?<label>Максимум хопов<input type="number" min={1} max={8} value={hops} onChange={e=>setHops(Number(e.target.value))}/></label>:<label>Порт цели<input type="number" min={1} max={65535} value={remotePort} onChange={e=>setRemotePort(Number(e.target.value))}/></label>}
 {remote==='http'&&<><label>Схема<select aria-label="Схема" value={scheme} onChange={e=>setScheme(e.target.value as 'http'|'https')}><option value="https">HTTPS</option><option value="http">HTTP</option></select></label><label>Путь<input required maxLength={1024} value={path} onChange={e=>setPath(e.target.value)}/></label></>}
 </fieldset>
 {caps.isError&&<p role="alert" className="error">Не удалось проверить возможности агентов.</p>}{!eligible.length&&<p>Нет агентов со свежим разрешением выбранного протокола.</p>}
 <div className="global-agent-picker">{eligible.map(n=><label key={n.id} className="global-check"><input type="checkbox" checked={chosen.includes(n.id)} disabled={batch.isPending||(!chosen.includes(n.id)&&chosen.length>=8)} onChange={e=>setSelected(old=>e.target.checked?[...old,n.id]:old.filter(id=>id!==n.id))}/>{n.name}</label>)}</div>
 <label className="global-check"><input type="checkbox" checked={remoteApproved} disabled={batch.isPending} onChange={e=>{e.stopPropagation();setRemoteApproved(e.target.checked)}}/>Подтверждаю разрешённую цель и профиль на всех выбранных агентах</label>
 <button disabled={!validBatch||batch.isPending}>Запустить удалённое сравнение</button>{batch.isError&&<p className="error" role="alert">{batch.error.message}</p>}{batch.isSuccess&&<p role="status">Сравнение принято: {batch.data.id}</p>}
 </form></details></section>
}
