# NetBird: подключение агентов без reverse proxy

**Статус:** инструкция для кандидата mTLS. Не применять к текущему main, пока этот кандидат не прошёл полный CI, не объединён и новый edge не опубликован. Физическая проверка на CasaOS/VPS ещё не выполнена. Все команды предполагают Docker Compose v2, Bash и существующую установку контроллера. Используйте собственные адреса.

## 1. CasaOS: подготовка

- Сохраните прежний Docker image ID и конфигурацию CasaOS, остановите контроллер и сделайте отдельную приватную резервную копию всего /DATA/AppData/dns-benchmark. Не удаляйте данные, не используйте down -v. При откате восстанавливайте старый образ **вместе** с копией до миграции SQLite.
- Выполните netbird status; найдите IPv4 именно домашнего сервера в диапазоне 100.64.0.0/10 (не публичный IP). Проверьте свободный порт 8443.
- В NetBird разрешите только группе доверенных VPS TCP 8443 до контроллера. Не публикуйте этот порт на 0.0.0.0 и не пробрасывайте его на маршрутизаторе. Сохраните действующие ограничения web-порта 8099.

## 2. Включение mTLS (один контроллер)

В существующую конфигурацию контейнера добавьте переменную NDC_AGENT_MTLS_IP=ВАШ_NETBIRD_IP и порт в формате ВАШ_NETBIRD_IP:8443:8443. Не меняйте текущий volume, порт 8099 и прочие переменные. Если UI CasaOS не позволяет указать адрес привязки, используйте исходный Compose (в его существующем каталоге/проекте), а не вторую установку. Дополнение:

```yaml
services:
  benchmark:
    environment:
      NDC_AGENT_MTLS_IP: "${NDC_AGENT_MTLS_IP:?Set controller NetBird IPv4}"
    ports:
      - "${NDC_AGENT_MTLS_IP:?Set controller NetBird IPv4}:8443:8443"
```

Этот файл в репозитории: deploy/compose.agent-control.yaml. При использовании Compose CLI из каталога уже установленного проекта, с его исходной конфигурацией:

```bash
read -rp 'NetBird IPv4 контроллера: ' NDC_AGENT_MTLS_IP
export NDC_AGENT_MTLS_IP
docker compose -f compose.yaml -f deploy/compose.agent-control.yaml config --quiet
docker compose -f compose.yaml -f deploy/compose.agent-control.yaml pull benchmark
docker compose -f compose.yaml -f deploy/compose.agent-control.yaml up -d benchmark
docker compose -f compose.yaml -f deploy/compose.agent-control.yaml ps
```

Используйте существующее имя проекта и не создавайте второй контроллер с тем же /data. Docker должен показать привязку именно NetBird IP:8443. Web остаётся на 8099. На контроллере внутри контейнера автоматически создаётся постоянный CA. После включения legacy machine API на 8099 блокируется, старые агенты требуют явной миграции.

## 3. Независимая проверка CA

На доверенном SSH-соединении с домашним сервером (из каталога Compose, с теми же аргументами проекта):

```bash
docker compose -f compose.yaml -f deploy/compose.agent-control.yaml exec -T benchmark \
  python -m backend.ndc.agent_control_pki fingerprint
```

В интерфейсе Agents → Установка агента на VPS отображаются NetBird URL, отпечаток SHA-256, кнопка скачать CA контроллера. Сверьте отпечаток с терминалом. Получите публичный CA через доверенный канал (например, SSH/SCP). При необходимости экспортируйте только публичный сертификат:

```bash
docker compose -f compose.yaml -f deploy/compose.agent-control.yaml exec -T benchmark \
  python -m backend.ndc.agent_control_pki public-ca > controller-ca.pem
```

Не копируйте agent-control-pki.json: там приватный ключ CA. Если веб-панель доступна по HTTP, не полагайтесь только на отображаемый в ней отпечаток; проверяйте скачанный файл независимо.

## 4. VPS UK-01

Скачайте из мастера compose.agent.yaml, agent.env, allowed-endpoints.json и controller-ca.pem. На VPS перенесите файлы по доверенному каналу в новый каталог, например /opt/ndc-agent (используйте права администратора только для установки).

```bash
cd /opt/ndc-agent
openssl x509 -in controller-ca.pem -noout -fingerprint -sha256
```

Сравните SHA-256 с выводом контроллера (openssl показывает двоеточия/верхний регистр). Файл agent.env должен содержать:

```dotenv
NDC_CONTROLLER_URL=https://ВАШ_NETBIRD_IP:8443
NDC_AGENT_PROTOCOL=2
NDC_AGENT_MTLS=1
NDC_AGENT_CA_FILE=/data/controller-ca.pem
```

```bash
read -rp 'NetBird IPv4 контроллера: ' NB_IP
curl --cacert controller-ca.pem -fsS "https://${NB_IP}:8443/health"
sudo install -d -m 700 -o 10001 -g 10001 agent-data
sudo install -m 600 -o 10001 -g 10001 controller-ca.pem agent-data/controller-ca.pem
sudo install -m 600 -o 10001 -g 10001 allowed-endpoints.json agent-data/allowed-endpoints.json
sudo docker compose --env-file agent.env -f compose.agent.yaml pull
```

Только теперь создайте приглашение Agents → Подключить агент → UK-01 / England. Токен действует 10 минут. Введите в терминале, не публикуйте его:

```bash
read -rs -p 'Enrollment token: ' TOKEN; printf '\n'
printf '%s\n' "$TOKEN" | sudo sh -c 'umask 077; cat > agent-data/enrollment-token; chown 10001:10001 agent-data/enrollment-token'
unset TOKEN
sudo docker compose --env-file agent.env -f compose.agent.yaml up -d
sudo docker compose --env-file agent.env -f compose.agent.yaml logs --tail=40 agent
```

Ожидается Agent identity ready; protocol 2; waiting for controller heartbeat. В Agents проверьте Online, mTLS 1.3 и срок выданного сертификата. Agent сам генерирует ключ; входящие порты на VPS не нужны. При повторной установке не удаляйте identity.json, control-key.pem и spool.json. Для миграции старого агента остановите его, сохраните старый каталог приватно, создайте новый каталог данных и используйте явную ротацию в UI. Не запускайте два экземпляра с одной identity.

## 5. VPS FI-01 и первый тест

Повторите шаг 4 на финской VPS с отдельным приглашением и новым ключом. Agents → Распределённый тест → https://cloudflare-dns.com/dns-query → IPv4 → Cold → 5 запросов → оба агента. Экспортируйте JSON. Затем Both; проверяйте результат, протокол, IP, ошибки, не только Online.

## 6. Проверка безопасности и диагностика

- `curl --cacert controller-ca.pem -fsS https://IP:8443/health` работает без клиентского сертификата; это только диагностика bootstrap TLS, не доказательство авторизации.
- POST /api/v1/agents/machine/v2/poll без клиентского сертификата возвращает 401; POST на обычный HTTP-порт 8099 возвращает 403 при включённом mTLS. GET /api/v1/agents на TLS-порту возвращает 404. Никогда не используйте curl -k.
- Если соединение не устанавливается: проверьте NetBird ACL/маршрут, привязку Docker порта, точное совпадение IP с SAN и CA, срок действия, время на обоих хостах, логи контроллера и агента. Если токен истёк/был использован без сохранённого identity, остановите агент и явно ротируйте приглашение. Не выводите identity.json, токен, приватные ключи.
- Клиентский сертификат 90 дней; автоматическое продление за 14 дней, при потере ответа возвращается тот же сертификат. Старый и новый сертификаты допускаются до истечения старого; отзыв/ротация в UI немедленно блокирует оба на уровне API. Серверный leaf 365 дней, пересоздаётся при перезапуске; живое обновление server leaf и CA rollover пока не реализованы. Утверждение о физической работе после миграции возможно только после реального теста.
- mTLS управления и mTLS прямых RTT/Throughput — разные контуры доверия. Для прямых измерений требуются отдельные сертификаты, явные локальные направления/параметры, привязка и ACL; этот этап проверяем после DNS. Не открывайте дополнительные порты заранее.

## Single-file Compose candidate (DNS profile)
The wizard exports one Compose with a unique project name per agent ID, persistent named volume, embedded public CA, explicit DNS allowlist and one-use invitation in an inline Compose config (requires Docker Compose >=2.23.1). No token in environment variables; the Compose file and Compose-generated config files are still sensitive until enrollment. Save with mode 0600 in a private directory, do not commit/share. Run `docker compose pull`, obtain the CA SHA-256 independently from the controller over trusted SSH, then `docker compose run --rm --no-deps bootstrap verify YOUR_SHA256`, then `docker compose up -d`. This explicit verification is required operationally; self-consistency of the embedded CA is not independent trust. After registration the wizard emits the same Compose project/volume without the token; replace file and `docker compose up -d`. Never use down -v; backup volume securely. Existing identities/keys/spools are never overwritten, allowlist/CA mismatches fail closed. Fresh volumes require an unexpired token. Advanced probes remain manual explicit approvals, not silently granted. Legacy multi-file setup remains available. CI and real VPS deployment pending, do not merge or install candidate until accepted.

Bootstrap now requires a persistent independently confirmed SHA-256 marker before first startup. The verification command writes it in the same named volume under the agent lock. Restart reuses the verified marker; a different CA is rejected. No private key is ever embedded. The generated project name and volume must not be changed. If the browser is HTTP and clipboard access is unavailable, select/copy the text manually or download. Current wizard generates the clean variant while the current invitation is still in the page; save that variant before closing the page. CI includes Python policy tests, actual Compose config mount and unprivileged named volume, and browser generator tests. All are pending exact-head CI.

## Compose runtime compatibility
CI 45864614680 passed bootstrap policy tests but Docker Compose rejected inline configs on read-only services. Move the inline config to an explicit one-shot `bootstrap` profile service: unprivileged, network_mode none, no capabilities, writable container root only during initialization, removed by `run --rm`. `docker compose --profile bootstrap pull`, then `docker compose run --rm --no-deps bootstrap verify YOUR_SHA256` confirms trust and prepares the shared persistent volume. `docker compose up -d` starts only the normal read-only agent, without inline config or token in its environment; runtime guard checks persisted binding, CA pin and identity before connecting. Replacing the registered Compose with its tokenless variant does not require re-running bootstrap. Existing multi-file installations unchanged. Docker integration and full CI pending.
