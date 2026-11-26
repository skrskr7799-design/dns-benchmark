import {useState} from 'react'
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
 {title:'INTELLIGENCE',items:[['/intelligence','DNS Intelligence','intelligence'],['/observatory','Network Observatory','activity'],['/time-machine','Network Time Machine','history'],['/global','Global Intelligence','agents'],['/dns-integrity','DNS Integrity & Privacy','lock'],['/protocol-lab','Protocol Laboratory','benchmark'],['/atlas','Internet Atlas','route'],['/website-xray','Website X-Ray','search'],['/network-twin','Network Twin','route'],['/scenario','Scenario Builder','activity'],['/chaos-lab','Chaos Lab','benchmark']]},
 {title:'MONITORING',items:[['/monitoring','Monitoring','activity'],['/history','История','history'],['/agents','Agents','agents']]},
 {title:'SYSTEM',items:[['/integrations','Integrations','integrations'],['/settings','Settings','settings']]}
] as const
function Shell(){
 const [open,setOpen]=useState(false)
 return <div className="shell"><aside className={open?'sidebar nav-open':'sidebar'}><div className="sidebar-top"><Brand/><button className="secondary mobile-menu" aria-label={open?'Закрыть меню':'Открыть меню'} aria-expanded={open} aria-controls="workspace-nav" onClick={()=>setOpen(v=>!v)}><Icon name={open?'close':'menu'}/></button></div><nav id="workspace-nav" aria-label="Навигация">{navGroups.map(g=><div className="nav-group" key={g.title}><div className="nav-title">{g.title}</div>{g.items.map(([to,label,icon])=><Link key={to} to={to} activeOptions={{exact:true}} onClick={()=>setOpen(false)}><Icon name={icon}/><span>{label}</span></Link>)}</div>)}</nav><div className="instance"><div className="instance-label"><Icon name="agents"/><div><b>Local instance</b><small>Obsidian Signature</small></div></div><Logout/></div></aside><main><Circuit/><div className="workspace-content"><Outlet/></div></main></div>
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
