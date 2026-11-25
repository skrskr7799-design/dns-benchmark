import type {ReactNode} from 'react'
const paths:Record<string,ReactNode>={
 overview:<><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
 intelligence:<><path d="m12 2 9 5v10l-9 5-9-5V7Z M3 7l9 5 9-5M12 12v10"/><circle cx="12" cy="7" r="1.4"/><path d="M7 14l2 2m6 0 2-2"/></>,
 benchmark:<><path d="M4 18a9 9 0 1 1 16 0M12 13l5-5M5 13h2M12 5v2M17 13h2"/><circle cx="12" cy="13" r="1"/></>,
 dns:<><path d="m12 3 9 5-9 5-9-5 9-5Zm-9 9 9 5 9-5M3 16l9 5 9-5"/></>,
 search:<><circle cx="10" cy="10" r="6"/><path d="m15 15 6 6"/></>,
 route:<><circle cx="5" cy="18" r="3"/><circle cx="19" cy="5" r="3"/><circle cx="19" cy="18" r="3"/><path d="m7 16 10-9M8 18h8"/></>,
 lock:<><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/></>,
 activity:<path d="M2 12h5l3-8 4 16 3-8h5"/>,
 history:<><circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 3"/></>,
 agents:<><rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6h.01M7 17h.01M11 6h6M11 17h6"/></>,
 integrations:<><path d="M9 3v5m6-5v5M6 8h12v3a6 6 0 0 1-12 0V8Zm6 9v4"/></>,
 settings:<><circle cx="12" cy="12" r="3"/><path d="m12 2 2 3 4-1 1 4 3 2-2 3 1 4-4 1-2 4-3-2-4 1-1-4-4-2 2-3-1-4 4-1 2-3Z"/></>,
 menu:<path d="M3 6h18M3 12h18M3 18h18"/>,
 close:<path d="m5 5 14 14M19 5 5 19"/>,
 arrow:<path d="M4 12h15m-6-6 6 6-6 6"/>,
 check:<><circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/></>,
 play:<path d="m8 5 12 7-12 7Z"/>,
 clock:<><circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 2"/></>,
 chart:<path d="M4 20V12m5 8V5m5 15V9m5 11V3"/>
}
export function Icon({name,size=20}:{name:string;size?:number}){return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.55" strokeLinecap="round" strokeLinejoin="round">{paths[name]??paths.dns}</svg>}
export function Brand(){return <div className="brand"><svg className="brand-mark" viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" aria-hidden="true"><path d="M32 3 57 17 57 47 32 61 7 47 7 17Z M7 17 32 32 57 17 M32 32V61"/><path d="M32 17 44 24 44 39 32 46 20 39 20 24Z M20 24 32 31 44 24 M32 31V46 M32 3V17 M7 47 20 39 M44 39 57 47"/></svg><div><b>DNS Benchmark</b><small>NETWORK / INTELLIGENCE</small></div></div>}
export function Circuit(){return <svg className="circuit" viewBox="0 0 620 155" fill="none" aria-hidden="true"><g stroke="currentColor" strokeWidth=".8"><path opacity=".25" d="M0 125h75l60-60h60l55-55h100l50 50h65l55-55h100M90 155l80-80h55l60 60h100l60-60h175M180 0l60 60h120l35-35h100l65 65h60"/><path opacity=".65" d="M10 110h90l55-55h65l50 50h65l55-55h100l45-45h85"/><path opacity=".2" d="M380 105l35-20 35 20v40l-35 20-35-20z"/></g><g fill="currentColor"><circle cx="155" cy="55" r="2.5"/><circle cx="270" cy="105" r="3"/><circle cx="390" cy="50" r="3"/><circle cx="535" cy="5" r="2"/></g></svg>}
