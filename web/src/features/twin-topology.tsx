import {useState,useId} from 'react'
import {type TwinGraph,type TwinReport} from '../shared/api'
const stateLabel:Record<string,string>={healthy:'Норма',failed:'Сбой',degraded:'Деградация',unknown:'Неизвестно'}
export function TwinTopology({graph,facts,selected,onSelect}:{graph:TwinGraph;facts:TwinReport['nodes'];selected:string;onSelect:(id:string)=>void}){
 const [page,setPage]=useState(0),[focus,setFocus]=useState(false)
 const marker=useId().replace(/:/g,'')
 const neighbors=new Set([selected,...graph.edges.filter(e=>e.source===selected||e.target===selected).flatMap(e=>[e.source,e.target])])
 const filtered=focus&&selected?graph.nodes.filter(n=>neighbors.has(n.id)):graph.nodes
 const pages=Math.max(1,Math.ceil(filtered.length/12)),p=Math.min(page,pages-1),nodes=filtered.slice(p*12,p*12+12)
 const height=Math.max(180,Math.ceil(nodes.length/3)*112+24)
 const locations=new Map(nodes.map((n,i)=>[n.id,{x:18+(i%3)*212,y:18+Math.floor(i/3)*112}]))
 const edges=graph.edges.filter(e=>locations.has(e.source)&&locations.has(e.target))
 return <div className="twin-topology"><div className="section-title"><h3>Dependency graph</h3><button className="secondary" disabled={!selected} aria-pressed={focus} onClick={()=>{setFocus(v=>!v);setPage(0)}}>Окрестность узла</button></div><p className="muted">Стрелка: зависимый узел → цель. {edges.length} из {graph.edges.length} связей на текущем листе; полный список связей доступен в деталях узла.</p>
 <div className="twin-canvas-scroll"><div className="twin-canvas" style={{height}}><svg aria-hidden="true" viewBox={`0 0 640 ${height}`} preserveAspectRatio="none"><defs><marker id={marker} markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto"><path d="M0 0 L6 3 L0 6Z" fill="#80D6DF"/></marker></defs>{edges.map(e=>{const a=locations.get(e.source)!,b=locations.get(e.target)!;const x=a.x+88,y=a.y+72,tx=b.x+88,ty=b.y;return <path key={e.source+e.target+e.kind} d={`M${x} ${y} C${x} ${y+24},${tx} ${ty-24},${tx} ${ty}`} fill="none" stroke={e.kind==='requires'?'#80D6DF':'#607D88'} strokeWidth={selected===e.source||selected===e.target?2:1} strokeDasharray={e.kind==='requires'?undefined:'5 5'} markerEnd={`url(#${marker})`}/>})}</svg>{nodes.map(n=>{const at=locations.get(n.id)!,f=facts.find(x=>x.id===n.id);return <button className="secondary twin-node twin-graph-node" style={{left:at.x,top:at.y}} key={n.id} aria-pressed={selected===n.id} onClick={()=>onSelect(n.id)}><small>{n.kind}</small><b title={n.name}>{n.name}</b><span data-state={f?.direct}>{f?stateLabel[f.direct]??f.direct:'Неизвестно'}</span></button>})}</div></div>
 <div className="controls"><button className="secondary" disabled={p===0} onClick={()=>setPage(p-1)}>Назад</button><span>{p+1} / {pages}</span><button className="secondary" disabled={p+1>=pages} onClick={()=>setPage(p+1)}>Далее</button></div></div>
}
