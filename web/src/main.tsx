import {createRoot} from 'react-dom/client'
import {QueryClient,QueryClientProvider,useQuery} from '@tanstack/react-query'
import {createRootRoute,createRoute,createRouter,createHashHistory,RouterProvider,Outlet,Link} from '@tanstack/react-router'
import {Benchmark,useStatus} from './features/benchmark'
import {History} from './features/history'
import {Stats} from './shared/results'
import {api} from './shared/api'
import './style.css'
const client=new QueryClient({defaultOptions:{queries:{retry:1,refetchOnWindowFocus:true}}})
const planned=['DNS Inspector','Connectivity','TLS Inspector','Routes','Monitoring','Agents','Settings']
function Shell(){return <div className="shell"><aside><div className="brand"><span className="logo">N</span><div><b>NETWORK</b><small>DIAGNOSTICS</small></div></div><div className="nav-title">WORKSPACE</div><nav aria-label="Навигация"><Link to="/" activeOptions={{exact:true}}>Overview</Link><Link to="/benchmark">DNS Benchmark</Link><Link to="/history">История</Link>{planned.map(n=><span className="planned" key={n}>{n}<small>План</small></span>)}</nav><div className="instance"><span className="dot"/> Standalone · alpha</div></aside><main><Outlet/></main></div>}
function Overview(){const status=useStatus(), history=useQuery({queryKey:['history'],queryFn:api.history});return <><header className="page-heading"><div><div className="eyebrow">WORKSPACE / OVERVIEW</div><h1>Network overview</h1><p>Локальная сетевая диагностика</p></div><Link className="primary-link" to="/benchmark">Новый тест</Link></header><Stats rows={status.data?.results.length?status.data.results:history.data?.[0]?.results??[]}/><section className="panel"><h2>Состояние приложения</h2><p>{status.isPending?'Подключение к API…':status.isError?'API недоступен':status.data?.running?'Бенчмарк выполняется':'API доступен · нет активного теста'}</p><p className="muted">Метрики относятся к текущему или последнему сохранённому запуску, а не непрерывному мониторингу.</p></section><section className="panel"><div className="section-title"><h2>Последние запуски</h2><Link to="/history">Вся история</Link></div>{history.isError?<p role="alert">Не удалось загрузить историю</p>:history.isPending?<p>Загрузка…</p>:history.data?.length?history.data.slice(0,5).map((r,i)=><div className="history-row" key={i}><span>{new Date(r.time*1000).toLocaleString('ru-RU')}</span><small>{r.results.length} серверов</small></div>):<p className="empty">Нет сохранённых запусков.</p>}</section></>}
const rootRoute=createRootRoute({component:Shell})
const indexRoute=createRoute({getParentRoute:()=>rootRoute,path:'/',component:Overview})
const benchmarkRoute=createRoute({getParentRoute:()=>rootRoute,path:'/benchmark',component:Benchmark})
const historyRoute=createRoute({getParentRoute:()=>rootRoute,path:'/history',component:History})
const router=createRouter({routeTree:rootRoute.addChildren([indexRoute,benchmarkRoute,historyRoute]),history:createHashHistory()})
declare module '@tanstack/react-router' {interface Register {router:typeof router}}
createRoot(document.getElementById('root')!).render(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>)
