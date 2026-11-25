import {useEffect,useState,type ReactNode} from 'react'
import {useQueryClient} from '@tanstack/react-query'
import {api,setSession,type Session} from '../shared/api'

export function AuthGate({children}:{children:ReactNode}){
 const client=useQueryClient()
 const [session,setAuth]=useState<Session|null>(null),[password,setPassword]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState('')
 function apply(value:Session){setSession(value);setAuth(value);if(!value.authenticated)client.clear()}
 async function load(){try{apply(await api.session());setError('')}catch{setError('Не удалось подключиться к серверу')}}
 useEffect(()=>{void load();const denied=()=>apply({authenticated:false,csrf:null});window.addEventListener('ndc:unauthorized',denied);return()=>window.removeEventListener('ndc:unauthorized',denied)},[])
 if(session?.authenticated)return <>{children}</>
 return <div className="auth-screen"><section className="panel auth-panel"><div className="brand"><span className="logo">N</span><div><b>NETWORK</b><small>DIAGNOSTICS</small></div></div><div className="eyebrow">PRIVATE WORKSPACE</div><h1>Вход в систему</h1><p>Локальная учётная запись владельца.</p>{session===null?<button onClick={()=>void load()}>Проверить подключение</button>:<form onSubmit={async e=>{e.preventDefault();setBusy(true);setError('');try{apply(await api.login(password));setPassword('')}catch(e){setError(e instanceof Error?e.message:'Ошибка входа')}finally{setBusy(false)}}}><label>Пароль<input type="password" autoComplete="current-password" value={password} onChange={e=>setPassword(e.target.value)} required maxLength={256}/></label><button className="auth-submit" disabled={busy||!password}>{busy?'Вход…':'Войти'}</button></form>}{error&&<p className="error" role="alert">{error}</p>}<small>Доступ только из доверенной сети.</small></section></div>
}
export function Logout(){const [error,setError]=useState(''),[busy,setBusy]=useState(false);return <><button className="secondary" disabled={busy} onClick={async()=>{setBusy(true);try{setSession(await api.logout());window.dispatchEvent(new Event('ndc:unauthorized'))}catch(e){setError(e instanceof Error?e.message:'Ошибка выхода')}finally{setBusy(false)}}}>Выйти</button>{error&&<small role="alert">{error}</small>}</>}
