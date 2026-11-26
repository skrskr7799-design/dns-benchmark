import {useEffect,useRef,useState} from 'react'
import {createRoot} from 'react-dom/client'
import {QueryClient,QueryClientProvider} from '@tanstack/react-query'
import {createRootRoute,createRoute,createRouter,createHashHistory,RouterProvider,Outlet,Link} from '@tanstack/react-router'
import {Benchmark} from './features/benchmark'
import {DNSIntelligence} from './features/intelligence'
import {GlobalIntelligence} from './features/global-intelligence'
import {DNSIntegrity} from './features/dns-integrity'
import {ProtocolLab} from './features/protocol-lab'
import {InternetAtlas,WebsiteXRay} from './features/atlas-xray'
import {NetworkTwin} from './features/network-twin'
import {ScenarioBuilder,ChaosLab} from './features/scenario-chaos'
import {Observatory} from './features/observatory'
import {TimeMachine} from './features/time-machine'
import {Providers} from './features/providers'
import {Inspector} from './features/inspector'
import {Connectivity,TLSInspector} from './features/network'
import {Routes} from './features/routes'
import {Monitoring} from './features/monitoring'
import {Agents} from './features/agents'
import {Diagnostics} from './features/diagnostics'
import {Integrations} from './features/integrations'
import {History} from './features/history'
import {Settings} from './features/settings'
import {applyAppearance,readAppearance} from './shared/preferences'
import {Overview} from './features/overview'
import {Brand,Icon,Circuit} from './shared/identity'
import {AuthGate,Logout} from './features/auth'
import './style.css'
applyAppearance(readAppearance())
const client=new QueryClient({defaultOptions:{queries:{retry:1,refetchOnWindowFocus:true}}})
const navGroups=[
 {title:'WORKSPACE',items:[['/','Overview','overview'],['/benchmark','DNS Benchmark','benchmark'],['/providers','Providers','dns'],['/inspector','DNS Inspector','search'],['/connectivity','Connectivity','route'],['/tls','TLS Inspector','lock'],['/routes','Routes','route'],['/diagnostics','Smart Diagnostics','activity']]},
 {title:'INTELLIGENCE',items:[['/intelligence','DNS Intelligence','intelligence'],['/observatory','Network Observatory','activity'],['/time-machine','Network Time Machine','history'],['/global','Global Intelligence','agents'],['/dns-integrity','DNS Integrity & Privacy','lock'],['/protocol-lab','Protocol Laboratory','protocol'],['/atlas','Internet Atlas','globe'],['/website-xray','Website X-Ray','scan'],['/network-twin','Network Twin','topology'],['/scenario','Scenario Builder','workflow'],['/chaos-lab','Chaos Lab','flask']]},
 {title:'MONITORING',items:[['/monitoring','Monitoring','activity'],['/history','История','history'],['/agents','Agents','agents']]},
 {title:'SYSTEM',items:[['/integrations','Integrations','integrations'],['/settings','Settings','settings']]}
] as const
function Shell(){
 const [open,setOpen]=useState(false),[filter,setFilter]=useState('')
 const visibleGroups=navGroups.map(g=>({...g,items:g.items.filter(([to,label])=>(label+' '+to).toLocaleLowerCase().includes(filter.trim().toLocaleLowerCase()))})).filter(g=>g.items.length)
 const trigger=useRef<HTMLButtonElement>(null),drawer=useRef<HTMLDivElement>(null),close=useRef<HTMLButtonElement>(null)
 useEffect(()=>{
  if(!open)return
  const media=window.matchMedia('(max-width:800px)')
  if(!media.matches){setOpen(false);return}
  const y=window.scrollY,body=document.body
  const previous={position:body.style.position,top:body.style.top,width:body.style.width,overflow:body.style.overflow}
  Object.assign(body.style,{position:'fixed',top:-y+'px',width:'100%',overflow:'hidden'})
  close.current?.focus()
  const resize=()=>{if(!media.matches)setOpen(false)}
  const key=(e:KeyboardEvent)=>{
   if(e.key==='Escape'){e.preventDefault();setOpen(false)}
   if(e.key==='Tab'){
    const items=Array.from(drawer.current?.querySelectorAll<HTMLElement>('a[href],button:not([disabled]),input:not([disabled])')??[]).filter(el=>el.getClientRects().length>0)
    if(!items.length)return
    const first=items[0],last=items[items.length-1]
    if(e.shiftKey&&(document.activeElement===first||!drawer.current?.contains(document.activeElement))){e.preventDefault();last.focus()}
    else if(!e.shiftKey&&(document.activeElement===last||!drawer.current?.contains(document.activeElement))){e.preventDefault();first.focus()}
   }
  }
  media.addEventListener('change',resize);document.addEventListener('keydown',key)
  return ()=>{media.removeEventListener('change',resize);document.removeEventListener('keydown',key);Object.assign(body.style,previous);window.scrollTo(0,y);if(media.matches)trigger.current?.focus({preventScroll:true})}
 },[open])
 return <div className="shell"><aside className={open?'sidebar nav-open':'sidebar'}><div className="sidebar-top" inert={open}><Brand/><button ref={trigger} className="secondary mobile-menu" aria-label="Открыть меню" aria-expanded={open} aria-controls="workspace-nav" onClick={()=>setOpen(true)}><Icon name="menu"/></button></div>{open&&<div className="nav-backdrop" aria-hidden="true" onClick={()=>setOpen(false)}/>}<div ref={drawer} className="nav-content" role={open?'dialog':undefined} aria-modal={open?true:undefined} aria-label={open?'Меню приложения':undefined}><div className="drawer-top"><Brand/><button ref={close} className="secondary mobile-menu" aria-label="Закрыть меню" onClick={()=>setOpen(false)}><Icon name="close"/></button></div><div className="nav-search"><Icon name="search" size={17}/><input aria-label="Поиск раздела" placeholder="Найти раздел" value={filter} onChange={e=>setFilter(e.target.value)}/>{filter&&<button className="secondary" aria-label="Очистить поиск" onClick={()=>setFilter('')}><Icon name="close" size={15}/></button>}</div><nav id="workspace-nav" aria-label="Навигация">{!visibleGroups.length&&<p className="nav-empty">Разделы не найдены</p>}{visibleGroups.map(g=><div className="nav-group" key={g.title}><div className="nav-title">{g.title}</div>{g.items.map(([to,label,icon])=><Link key={to} to={to} activeOptions={{exact:true}} onClick={()=>{setFilter('');setOpen(false)}}><Icon name={icon}/><span>{label}</span></Link>)}</div>)}</nav><div className="instance"><div className="instance-label"><Icon name="agents"/><div><b>Local instance</b><small>Obsidian Signature</small></div></div><Logout/></div></div></aside><main inert={open}><Circuit/><div className="workspace-content"><Outlet/></div></main></div>
}
const rootRoute=createRootRoute({component:Shell})
const indexRoute=createRoute({getParentRoute:()=>rootRoute,path:'/',component:Overview})
const benchmarkRoute=createRoute({getParentRoute:()=>rootRoute,path:'/benchmark',component:Benchmark})
const intelligenceRoute=createRoute({getParentRoute:()=>rootRoute,path:'/intelligence',component:DNSIntelligence})
const observatoryRoute=createRoute({getParentRoute:()=>rootRoute,path:'/observatory',component:Observatory})
const scenarioRoute=createRoute({getParentRoute:()=>rootRoute,path:'/scenario',component:ScenarioBuilder})
const chaosRoute=createRoute({getParentRoute:()=>rootRoute,path:'/chaos-lab',component:ChaosLab})
const twinRoute=createRoute({getParentRoute:()=>rootRoute,path:'/network-twin',component:NetworkTwin})
const atlasRoute=createRoute({getParentRoute:()=>rootRoute,path:'/atlas',component:InternetAtlas})
const xrayRoute=createRoute({getParentRoute:()=>rootRoute,path:'/website-xray',component:WebsiteXRay})
const labRoute=createRoute({getParentRoute:()=>rootRoute,path:'/protocol-lab',component:ProtocolLab})
const integrityRoute=createRoute({getParentRoute:()=>rootRoute,path:'/dns-integrity',component:DNSIntegrity})
const globalRoute=createRoute({getParentRoute:()=>rootRoute,path:'/global',component:GlobalIntelligence})
const timeMachineRoute=createRoute({getParentRoute:()=>rootRoute,path:'/time-machine',component:TimeMachine})
const providersRoute=createRoute({getParentRoute:()=>rootRoute,path:'/providers',component:Providers})
const inspectorRoute=createRoute({getParentRoute:()=>rootRoute,path:'/inspector',component:Inspector})
const connectivityRoute=createRoute({getParentRoute:()=>rootRoute,path:'/connectivity',component:Connectivity})
const tlsRoute=createRoute({getParentRoute:()=>rootRoute,path:'/tls',component:TLSInspector})
const routesRoute=createRoute({getParentRoute:()=>rootRoute,path:'/routes',component:Routes})
const monitoringRoute=createRoute({getParentRoute:()=>rootRoute,path:'/monitoring',component:Monitoring})
const agentsRoute=createRoute({getParentRoute:()=>rootRoute,path:'/agents',component:Agents})
const diagnosticsRoute=createRoute({getParentRoute:()=>rootRoute,path:'/diagnostics',component:Diagnostics})
const integrationsRoute=createRoute({getParentRoute:()=>rootRoute,path:'/integrations',component:Integrations})
const settingsRoute=createRoute({getParentRoute:()=>rootRoute,path:'/settings',component:Settings})
const historyRoute=createRoute({getParentRoute:()=>rootRoute,path:'/history',component:History})
const router=createRouter({routeTree:rootRoute.addChildren([indexRoute,benchmarkRoute,intelligenceRoute,observatoryRoute,timeMachineRoute,globalRoute,integrityRoute,labRoute,atlasRoute,xrayRoute,twinRoute,scenarioRoute,chaosRoute,providersRoute,inspectorRoute,connectivityRoute,tlsRoute,routesRoute,monitoringRoute,agentsRoute,diagnosticsRoute,integrationsRoute,settingsRoute,historyRoute]),history:createHashHistory()})
declare module '@tanstack/react-router' {interface Register {router:typeof router}}
createRoot(document.getElementById('root')!).render(<QueryClientProvider client={client}><AuthGate><RouterProvider router={router}/></AuthGate></QueryClientProvider>)
