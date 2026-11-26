import {useState} from 'react'
import {Icon} from '../shared/identity'
import type {AgentInvite} from '../shared/api'

// Keep this exact template aligned with deploy/compose.agent.yaml.
export const AGENT_COMPOSE="name: ndc-agent\nservices:\n  agent:\n    image: \"${NDC_AGENT_IMAGE:-ghcr.io/skrskr7799-design/dns-benchmark:edge}\"\n    command: [\"python\",\"-m\",\"backend.ndc.agent_client\"]\n    environment:\n      NDC_CONTROLLER_URL: \"${NDC_CONTROLLER_URL:?Set verified HTTPS controller origin}\"\n      NDC_AGENT_PROTOCOL: \"${NDC_AGENT_PROTOCOL:-2}\"\n      NDC_AGENT_CA_FILE: \"${NDC_AGENT_CA_FILE:-}\"\n      NDC_AGENT_MTLS: \"${NDC_AGENT_MTLS:-0}\"\n      NDC_CA_FILE: \"${NDC_CA_FILE:-}\"\n      NDC_ALLOWED_CIDRS: \"${NDC_ALLOWED_CIDRS:-}\"\n    volumes:\n      - ./agent-data:/data\n    healthcheck:\n      disable: true\n    pids_limit: 64\n    mem_limit: 384m\n    stop_grace_period: 20s\n    restart: unless-stopped\n    security_opt:\n      - no-new-privileges:true\n    cap_drop:\n      - ALL\n    read_only: true\n    tmpfs:\n      - /tmp:size=32m\n"
const DEFAULT_ENDPOINTS=["https://cloudflare-dns.com/dns-query","https://dns.google/dns-query","udp://1.1.1.1","udp://8.8.8.8"]
const INSTALL_COMMANDS="# В новой папке на VPS, рядом с тремя скачанными файлами:\n# compose.agent.yaml, agent.env, allowed-endpoints.json\nsudo install -d -m 700 -o 10001 -g 10001 agent-data\nsudo install -m 600 -o 10001 -g 10001 allowed-endpoints.json agent-data/allowed-endpoints.json\n\n# Введите одноразовый токен из панели (символы не отображаются).\nread -r -s -p 'Enrollment token: ' TOKEN; printf '\\n'\nprintf '%s\\n' \"$TOKEN\" | sudo sh -c 'umask 077; cat > agent-data/enrollment-token; chown 10001:10001 agent-data/enrollment-token'\nunset TOKEN\n\nsudo docker compose --env-file agent.env -f compose.agent.yaml pull\nsudo docker compose --env-file agent.env -f compose.agent.yaml up -d\nsudo docker compose --env-file agent.env -f compose.agent.yaml logs --tail=40 agent"
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
export function AgentSetup({invite,connected}:{invite:AgentInvite|null;connected:boolean}){
 const [origin,setOrigin]=useState(()=>window.location.protocol==='https:'?window.location.origin:'')
 const [selected,setSelected]=useState<string[]>(DEFAULT_ENDPOINTS)
 const safeOrigin=verifiedOrigin(origin)
 return <section className="panel agent-setup"><h2><Icon name="agents"/> Установка агента на VPS</h2>
 <p>Docker Compose · протокол 2 · исходящие подключения. Входящие порты для обычных измерений не нужны.</p>
 <ol className="agent-steps"><li><b>Подготовьте приватный HTTPS контроллера</b><p>Агенту нужен доступный HTTPS origin с проверяемым сертификатом. Для NetBird используйте приватный reverse proxy и DNS-имя, совпадающее с сертификатом. HTTP на 8099 не подходит. Не отключайте проверку сертификата.</p>
 <label>HTTPS контроллера<input aria-label="HTTPS контроллера" value={origin} maxLength={2048} onChange={e=>setOrigin(e.target.value)} placeholder="https://ndc.example.net"/></label>{origin&&!safeOrigin&&<p className="error">Укажите HTTPS origin без пути, логина, пароля или параметров.</p>}
 {safeOrigin&&<p className="muted">Проверка с VPS: <code>curl -fsS {safeOrigin}/health</code>. При частном CA используйте его доверенный публичный сертификат и NDC_AGENT_CA_FILE (см. документацию).</p>}</li>
 <li><b>Выберите разрешённые DNS-резолверы</b><div className="dns-checks">{DEFAULT_ENDPOINTS.map(e=><label key={e}><input type="checkbox" checked={selected.includes(e)} onChange={v=>setSelected(old=>v.target.checked?[...old,e]:old.filter(x=>x!==e))}/>{e}</label>)}</div><p className="muted">Для других целей редактируйте allowed-endpoints.json на VPS. TCP/TLS/HTTP/Route требуют отдельного allowed-probes.json; прямой RTT/Throughput — отдельного mTLS и разрешений.</p></li>
 <li><b>Скачайте конфигурацию</b><div className="controls"><button className="secondary" onClick={()=>downloadText('compose.agent.yaml',AGENT_COMPOSE)}>Скачать Compose</button><button className="secondary" disabled={!safeOrigin} onClick={()=>downloadText('agent.env','NDC_CONTROLLER_URL='+safeOrigin+'\nNDC_AGENT_PROTOCOL=2\n')}>Скачать agent.env</button><button className="secondary" disabled={!selected.length} onClick={()=>downloadText('allowed-endpoints.json',JSON.stringify(selected,null,2)+'\n')}>Скачать allowlist</button></div><p className="muted">Токен и учётные данные не включаются в скачиваемые файлы. Перенесите три файла на VPS в отдельную папку. На существующем агенте не перезаписывайте identity.json и spool.json.</p></li>
 <li><b>Создайте приглашение и запустите</b><p>Используйте приглашение в блоке выше: действует 10 минут. Для новой установки выполните команды в Bash на VPS. Для обновления уже зарегистрированного агента достаточно pull / up -d с сохранением данных и URL.</p><pre className="agent-json agent-install-code">{INSTALL_COMMANDS}</pre></li>
 <li><b>Убедитесь, что агент подключился</b><p>{connected?'Агент Online. Можно запускать распределённый DNS-тест с 2–8 узлами.':invite?'Приглашение создано. После запуска ожидайте Online в инфраструктуре; при ошибке проверьте логи и HTTPS.':'Создайте приглашение и следите за статусом в инфраструктуре.'}</p><p className="muted">Не присылайте identity.json, токены, приватные ключи или пароли. Локация — ваша подпись, не измеренная геолокация.</p></li></ol>
 </section>
}
