import {useEffect,useState} from 'react'
import {Icon} from '../shared/identity'
import {api,type AgentInvite} from '../shared/api'
import {useQuery} from '@tanstack/react-query'
import {agentCompose,DNS_ENDPOINTS} from '../shared/agent-compose'

// Keep this exact template aligned with deploy/compose.agent.yaml.
export const AGENT_COMPOSE="name: ndc-agent\nservices:\n  agent:\n    image: \"${NDC_AGENT_IMAGE:-ghcr.io/skrskr7799-design/dns-benchmark:edge}\"\n    command: [\"python\",\"-m\",\"backend.ndc.agent_client\"]\n    environment:\n      NDC_CONTROLLER_URL: \"${NDC_CONTROLLER_URL:?Set verified HTTPS controller origin}\"\n      NDC_AGENT_PROTOCOL: \"${NDC_AGENT_PROTOCOL:-2}\"\n      NDC_AGENT_CA_FILE: \"${NDC_AGENT_CA_FILE:-}\"\n      NDC_AGENT_MTLS: \"${NDC_AGENT_MTLS:-0}\"\n      NDC_CA_FILE: \"${NDC_CA_FILE:-}\"\n      NDC_ALLOWED_CIDRS: \"${NDC_ALLOWED_CIDRS:-}\"\n    volumes:\n      - ./agent-data:/data\n    healthcheck:\n      disable: true\n    pids_limit: 64\n    mem_limit: 384m\n    stop_grace_period: 20s\n    restart: unless-stopped\n    security_opt:\n      - no-new-privileges:true\n    cap_drop:\n      - ALL\n    read_only: true\n    tmpfs:\n      - /tmp:size=32m\n"
const DEFAULT_ENDPOINTS=DNS_ENDPOINTS
const INSTALL_COMMANDS="# В новой папке на VPS, рядом с тремя скачанными файлами:\n# compose.agent.yaml, agent.env, allowed-endpoints.json\nsudo install -d -m 700 -o 10001 -g 10001 agent-data\nsudo install -m 600 -o 10001 -g 10001 allowed-endpoints.json agent-data/allowed-endpoints.json\n\nsudo docker compose --env-file agent.env -f compose.agent.yaml pull\n\n# Введите одноразовый токен из панели (символы не отображаются).\nread -r -s -p 'Enrollment token: ' TOKEN; printf '\\n'\nprintf '%s\\n' \"$TOKEN\" | sudo sh -c 'umask 077; cat > agent-data/enrollment-token; chown 10001:10001 agent-data/enrollment-token'\nunset TOKEN\n\nsudo docker compose --env-file agent.env -f compose.agent.yaml up -d\nsudo docker compose --env-file agent.env -f compose.agent.yaml logs --tail=40 agent"
function downloadText(name:string,value:string){
 const url=URL.createObjectURL(new Blob([value],{type:'text/plain;charset=utf-8'}))
 const a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)
}
export function verifiedOrigin(raw:string){
 try{
  const u=new URL(raw.trim())
  if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||u.pathname!=='/'||!u.hostname)return null
  if(!/^https:\/\/(?:[a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\])(?::[0-9]{1,5})?$/.test(u.origin))return null
  return u.origin
 }catch{return null}
}
export function AgentSetup({invite,connected,enrolled}:{invite:AgentInvite|null;connected:boolean;enrolled:boolean}){
 const [origin,setOrigin]=useState(()=>window.location.protocol==='https:'?window.location.origin:'')
 const [selected,setSelected]=useState<string[]>(DEFAULT_ENDPOINTS)
 const [memory,setMemory]=useState<256|384|512>(384),[restart,setRestart]=useState(true),[now,setNow]=useState(Date.now()/1000),[copied,setCopied]=useState('')
 useEffect(()=>{const t=setInterval(()=>setNow(Date.now()/1000),1000);return()=>clearInterval(t)},[])
 useEffect(()=>{setCopied('')},[invite?.id,invite?.token])
 const trust=useQuery({queryKey:['agent-control-trust'],queryFn:api.agentControlTrust,retry:false})
 const mtls=trust.data?.enabled===true?trust.data:null
 const safeOrigin=verifiedOrigin(mtls?mtls.origin:origin)
 let generated=''
 if(mtls&&invite&&selected.length&&(enrolled||invite.expires_at>now)){
  try{generated=agentCompose(mtls,invite,{memory,restart,endpoints:selected},enrolled)}catch{/* invalid input: no secret exported */}
 }
 async function copyCompose(){try{await navigator.clipboard.writeText(generated);setCopied('Скопировано')}catch{setCopied('Выделите текст вручную или скачайте файл.')}}
 const install=mtls?INSTALL_COMMANDS.replace('sudo install -m 600 -o 10001 -g 10001 allowed-endpoints.json agent-data/allowed-endpoints.json','sudo install -m 600 -o 10001 -g 10001 allowed-endpoints.json agent-data/allowed-endpoints.json\nsudo install -m 600 -o 10001 -g 10001 controller-ca.pem agent-data/controller-ca.pem'):INSTALL_COMMANDS
 return <section className="panel agent-setup"><h2><Icon name="agents"/> Установка агента на VPS</h2>
 <p>Docker Compose · протокол 2 · исходящие подключения. Входящие порты для обычных измерений не нужны.</p>{trust.isError&&<p role="alert" className="error">Не удалось проверить режим mTLS. Повторите загрузку страницы.</p>}
 <ol className="agent-steps"><li><b>Подготовьте приватный HTTPS контроллера</b>{mtls?<><p>NetBird mTLS включён: TLS 1.3, сертификат и токен. Reverse proxy не требуется. Передайте публичный CA по доверенному каналу. Сверьте SHA-256 с выводом на контроллере через доверенный SSH: python -m backend.ndc.agent_control_pki fingerprint (в контейнере).</p><p className="dns-value">CA SHA-256: {mtls.sha256}</p><button className="secondary" onClick={()=>downloadText('controller-ca.pem',mtls.ca_pem)}>Скачать CA контроллера</button></>:<p>Для прямого NetBird mTLS задайте NDC_AGENT_MTLS_IP и привязку порта 8443 на контроллере. Иначе нужен проверенный HTTPS origin. HTTP на 8099 не подходит.</p>}
 <label>HTTPS контроллера<input aria-label="HTTPS контроллера" value={mtls?mtls.origin:origin} readOnly={!!mtls} maxLength={2048} onChange={e=>setOrigin(e.target.value)} placeholder="https://ndc.example.net"/></label>{origin&&!safeOrigin&&<p className="error">Укажите HTTPS origin без пути, логина, пароля или параметров.</p>}
 {safeOrigin&&<p className="muted">Проверка с VPS: <code>curl {mtls?'--cacert controller-ca.pem ':''}-fsS {safeOrigin}/health</code>. Не отключайте проверку сертификата.</p>}</li>
 <li><b>Выберите разрешённые DNS-резолверы</b><div className="dns-checks">{DEFAULT_ENDPOINTS.map(e=><label key={e}><input type="checkbox" checked={selected.includes(e)} onChange={v=>setSelected(old=>v.target.checked?[...old,e]:old.filter(x=>x!==e))}/>{e}</label>)}</div><p className="muted">Для других целей редактируйте allowed-endpoints.json на VPS. TCP/TLS/HTTP/Route требуют отдельного allowed-probes.json; прямой RTT/Throughput — отдельного mTLS и разрешений.</p></li>
 {mtls&&<li><b>Быстрая установка · один Compose</b><p>Профиль DNS. Контроллер подставлен автоматически; ключ создаётся только на VPS. Docker Compose 2.23.1 или новее. Одноразовый bootstrap без сети подготавливает volume; рабочий агент остаётся read-only. Используйте новый каталог и проверенный SSH-канал.</p>
 <div className="form-grid"><label>Память агента<select value={memory} onChange={e=>setMemory(Number(e.target.value) as 256|384|512)}><option value={256}>256 MB</option><option value={384}>384 MB</option><option value={512}>512 MB</option></select></label><label>Перезапуск<span><input type="checkbox" checked={restart} onChange={e=>setRestart(e.target.checked)}/> Автоматически</span></label></div>
 <p className="muted">Подготовьте VPS и образ до создания приглашения: срок 10 минут. Скачанный Compose с активным токеном — секрет; chmod 600, не отправляйте его в чат или Git. После регистрации замените на вариант без токена, сохраняя volume.</p>
 {!invite?<p>Создайте приглашение в блоке «Подключить агент» выше.</p>:!enrolled&&invite.expires_at<=now?<p className="error">Приглашение истекло. Используйте явную ротацию для этого агента.</p>:generated?<><div className="section-title"><h3>{enrolled?'Compose без токена':'Готовый compose.yaml'}</h3><span>{enrolled?'Зарегистрирован':Math.max(0,Math.ceil(invite.expires_at-now))+' сек.'}</span></div>
 <textarea className="agent-install-code" rows={12} aria-label="Готовый Compose" value={generated} readOnly spellCheck={false} autoComplete="off"/>
 <div className="controls"><button className="secondary" onClick={copyCompose}>Копировать Compose</button><button className="secondary" onClick={()=>downloadText('compose.yaml',generated)}>Скачать готовый Compose</button></div><p role="status">{copied}</p>
 <p>Сначала подтвердите отпечаток CA из доверенного SSH контроллера. Без этой однократной проверки агент не начнёт регистрацию. На VPS в новом каталоге:</p><pre className="agent-json agent-install-code">{'umask 077\nmkdir -p ~/ndc-agent; cd ~/ndc-agent\nnano compose.yaml\nchmod 600 compose.yaml\ndocker compose --profile bootstrap pull\n# Подставьте отпечаток из SSH контроллера, а не из этого файла:\ndocker compose run --rm --no-deps bootstrap verify ВАШ_SHA256\ndocker compose up -d\ndocker compose logs --tail=40 agent'}</pre></>:<p className="error">Выберите хотя бы один DNS-резолвер и проверьте параметры.</p>}
 {enrolled&&<p>После замены файла выполните docker compose up -d. Не удаляйте volume. Старые копии Compose могут содержать уже погашенный токен.</p>}</li>}
 <li><b>Скачайте конфигурацию (ручной вариант)</b><div className="controls"><button className="secondary" onClick={()=>downloadText('compose.agent.yaml',AGENT_COMPOSE)}>Скачать Compose</button><button className="secondary" disabled={!safeOrigin||trust.isPending||trust.isError} onClick={()=>downloadText('agent.env','NDC_CONTROLLER_URL='+safeOrigin+'\nNDC_AGENT_PROTOCOL=2\n'+(mtls?'NDC_AGENT_MTLS=1\nNDC_AGENT_CA_FILE=/data/controller-ca.pem\n':''))}>Скачать agent.env</button><button className="secondary" disabled={!selected.length} onClick={()=>downloadText('allowed-endpoints.json',JSON.stringify(selected,null,2)+'\n')}>Скачать allowlist</button></div><p className="muted">Токен и учётные данные не включаются в скачиваемые файлы. Перенесите скачанные файлы (в режиме mTLS также CA) на VPS в отдельную папку. На существующем агенте не перезаписывайте identity.json и spool.json.</p></li>
 <li><b>Подготовьте образ, затем создайте приглашение и запустите</b><p>Сначала скачайте образ (pull), затем используйте приглашение в блоке выше: действует 10 минут. Для новой установки выполните команды в Bash на VPS. Для обычного обновления используйте pull / up -d. Переход со старого HTTPS на mTLS требует остановки агента, ротации в панели и отдельной новой директории данных; старую сохраните приватно.</p><pre className="agent-json agent-install-code">{install}</pre></li>
 <li><b>Убедитесь, что агент подключился</b><p>{connected?'Агент Online. Можно запускать распределённый DNS-тест с 2–8 узлами.':invite?'Приглашение создано. После запуска ожидайте Online в инфраструктуре; при ошибке проверьте логи и HTTPS.':'Создайте приглашение и следите за статусом в инфраструктуре.'}</p><p className="muted">Не присылайте identity.json, токены, приватные ключи или пароли. Локация — ваша подпись, не измеренная геолокация.</p></li></ol>
 </section>
}
