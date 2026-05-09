# botguard

`botguard` — это маленький Go-демон, который превращает access-лог Caddy в
динамический IP-блоклист на базе **FCrDNS** (Forward-Confirmed Reverse DNS):

```
IP → PTR → имя хоста → A/AAAA → {IPs}
                         └── исходный IP в списке? значит имя подтверждено.
```

Без второго шага любой может выставить PTR `googlebot.com.` на свой IP и
притвориться Googlebot'ом. С FCrDNS такая подделка отсекается сразу.

## Поток данных

```
Caddy access log (JSON file) ──▶ tailer ──▶ pipeline ──▶ SQLite кеш
                                              │
                                              ▼
                                   FCrDNS resolver
                                              │
                  ┌───────────────────────────┼───────────────────┐
                  ▼                           ▼                   ▼
              allow-list                  deny-list          neutral
            (UA + host pattern)         (UA + host pattern)   (нет правила)
                  │                           │
                  └────► пишем в blocked.caddy ◀──── debounce 30s
                                              │
                                              ▼
                                   POST /load на Caddy admin API
```

Блокировка реализована через статический сниппет `blocked.caddy`, который
импортируется production-Caddyfile'ом потребителя. После пакетного обновления
botguard пинает Caddy через admin API — zero-downtime reload.

## Структура

```
.
├── cmd/
│   ├── botguard/          # демон (long-running)
│   └── botctl/            # CLI: report, status, whois, block, unblock, purge
├── internal/
│   ├── config/            # YAML-конфиг + длительности
│   ├── store/             # SQLite (WAL, single-writer)
│   ├── resolver/          # FCrDNS + worker pool
│   ├── rules/             # движок правил allow/deny
│   ├── tailer/            # follow access.log с обработкой ротации
│   ├── caddyctl/          # рендер сниппета + reload через admin API
│   ├── pipeline/          # склейка всего вышеперечисленного
│   ├── server/            # HTTP /healthz, /stats, /blocked (basic auth)
│   └── model/             # общие типы
└── config/
    ├── botguard.yaml
    └── rules.yaml
```

## Совместимость

- **Go**: 1.22+
- **Caddy**: 2.x с включённым admin API. По умолчанию botguard вызывает
  `POST /adapt` + `POST /load`, поэтому путь к `Caddyfile` должен быть
  доступен изнутри контейнера botguard.
- **OS**: Linux/macOS (поддерживаемые fsnotify/sqlite). В прод собираем
  multi-arch образ `linux/amd64,linux/arm64`.

## Установка

### Docker (рекомендуется)

```bash
docker pull ghcr.io/postfriday/botguard:latest
```

Минимальный запуск рядом с Caddy:

```yaml
services:
  caddy:
    image: caddy:2
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_logs:/var/log/caddy
      - caddy_dynamic:/etc/caddy/dynamic
    ports: ["80:80", "443:443"]
    networks: [internal]

  botguard:
    image: ghcr.io/postfriday/botguard:latest
    depends_on: [caddy]
    volumes:
      - caddy_logs:/var/log/caddy:ro                # botguard читает access.log
      - caddy_dynamic:/etc/caddy/dynamic            # botguard пишет blocked.caddy
      - ./Caddyfile:/etc/caddy/Caddyfile:ro         # нужен для /adapt
      - botguard_data:/var/lib/botguard             # SQLite кеш
      - ./botguard.yaml:/etc/botguard/botguard.yaml:ro
      - ./rules.yaml:/etc/botguard/rules.yaml:ro
    networks: [internal]

volumes:
  caddy_logs: {}
  caddy_dynamic: {}
  botguard_data: {}

networks:
  internal: {}
```

В Caddyfile нужны три вещи: открытый admin API, JSON-логи и `import` сниппета.

```caddy
{
    admin 0.0.0.0:2019    # admin API на internal docker-сети
}

example.com {
    @bad_bots header_regexp User-Agent "(?i)(SemrushBot|AhrefsBot|MJ12bot|ChatGPT-User)"
    respond @bad_bots 403

    import /etc/caddy/dynamic/*.caddy   # сниппет от botguard

    log {
        output file /var/log/caddy/access.log {
            roll_size 100MiB
            roll_keep 7
        }
        format json
    }
}
```

### Из исходников

```bash
git clone https://github.com/postfriday/botguard.git
cd botguard
go build ./cmd/botguard ./cmd/botctl
```

## Конфигурация

`botguard.yaml` (полный пример — в `config/botguard.yaml`):

```yaml
log:
  path: /var/log/caddy/access.log
  poll_interval: 250ms

cache:
  path: /var/lib/botguard/botguard.db
  ttl:
    allow:    168h    # 7 дней
    deny:     720h    # 30 дней
    neutral:  168h
    nxdomain: 1h
    error:    5m
  block_retention: 2160h   # IP остаётся в blocked.caddy 90 дней

resolver:
  workers: 8
  timeout: 3s
  max_in_flight: 64
  servers: []           # пусто → системный резолвер

caddy:
  admin_url:    http://caddy:2019
  caddyfile:    /etc/caddy/Caddyfile
  snippet_path: /etc/caddy/dynamic/blocked.caddy
  reload_debounce: 30s
  reload_command: ""    # если задан, выполняется shell-командой вместо admin API
  config_path: ""       # если задан — PATCH /config/<path> вместо /adapt + /load

server:
  listen: ""            # ":8088" — включает /healthz, /stats, /blocked
  basic_auth:
    user: ""
    pass: ""

rules:
  path: /etc/botguard/rules.yaml
```

### Режимы перезагрузки Caddy

Caddy admin API даёт три способа применить изменения; botguard выбирает их в
таком приоритете:

1. **`reload_command`** — произвольная shell-команда. Используется в dev-стенде
   (`true` как no-op) и в экзотических установках без admin API.
2. **`config_path`** — `PATCH /config/<path>` с JSON-массивом IP. Caddy
   перезагружает только указанный узел — заметно дешевле полного reload и
   сохраняет уже установленные TLS-handshake'и. Требует, чтобы в Caddyfile
   (или JSON-конфиге) уже существовал matcher с известным `@id`. Минимальный
   пример:

   ```caddy
   example.com {
       route {
           @botguard_blocked {
               remote_ip
           }
           respond @botguard_blocked 403
       }
   }
   ```

   Затем в `botguard.yaml`:

   ```yaml
   caddy:
     config_path: /id/botguard_blocked/match/0/remote_ip/ranges
   ```

   Снeпет `blocked.caddy` всё равно пишется на диск — он остаётся источником
   правды для `/blocked` и удобен для отладки, но Caddy его уже не читает.

3. **По умолчанию** — `POST /adapt` + `POST /load`. Полный reload Caddyfile
   через admin API. Работает с любой структурой конфига, но дороже.

### Правила

YAML, first-match-wins. См. `config/rules.yaml` — там готовые allow для
LLM-обучающих ботов (ClaudeBot, GPTBot, meta-externalagent, Amazonbot,
Bytespider, CCBot) и deny для on-demand AI-fetchers (ChatGPT-User,
Perplexity-User, OAI-SearchBot, PerplexityBot) плюс типовых SEO-скраперов.

```yaml
rules:
  - name: allow-gptbot
    action: allow
    ua_regex: "GPTBot"
    hostname_suffix: ["openai.com"]
    require_fcrdns: true

  - name: deny-chatgpt-user
    action: deny
    ua_regex: "ChatGPT-User"

  - name: deny-seo-hosts
    action: deny
    require_fcrdns: true
    hostname_suffix: [semrush.com, ahrefs.com, mj12bot.com, moz.com]
```

### TTL кеша (дифференцированные)

| Состояние                       | TTL по умолчанию |
|---------------------------------|------------------|
| confirmed allow                 | 7 дней           |
| confirmed deny (rule match)     | 30 дней          |
| neutral (резолвится, нет правил)| 7 дней           |
| no PTR / NXDOMAIN               | 1 час            |
| SERVFAIL / timeout              | 5 минут          |

Блок на уровне Caddy держится дольше — `block_retention: 90d`.

## CLI

```bash
botctl status                     # сводка по кешу/событиям
botctl report --since 7d          # топ доменов-нарушителей (markdown)
botctl report --since 24h --format csv
botctl whois 203.0.113.10         # что мы знаем про IP
botctl block 203.0.113.10 spam    # ручной override → деny
botctl unblock 203.0.113.10       # ручной override → allow (false positive)
botctl drop-override 203.0.113.10 # снять любой override
botctl purge                      # подчистить просроченный кеш
```

CLI ходит напрямую в SQLite, поэтому работает и когда демон остановлен.

## Метрики и наблюдаемость

HTTP-эндпоинт включается через `server.listen: ":8088"`:

```
GET  /healthz            # liveness — 200 OK
GET  /stats?since=24h    # JSON: топ rule_pattern по событиям
GET  /blocked            # JSON: текущие deny-IP с UA/hostname
```

`/stats` и `/blocked` защищены basic auth, если настроен `server.basic_auth`.

Healthcheck в Docker-образе уже настроен (`pgrep -x botguard`), поэтому
оркестратору достаточно поллить `/healthz`, чтобы заметить дегенерацию
горутин при формально живом процессе.

## Локальная разработка

Все Go-команды живут в `Taskfile.yml` и выполняются внутри docker-контейнера
`golang:1.22`, чтобы не зависеть от локальной установки Go. Нужен только
[`task`](https://taskfile.dev) и Docker.

```bash
task            # список целей
task tidy       # go mod tidy
task vet        # go vet ./...
task test       # go test -race -count=1 ./...
task lint       # golangci-lint run
task build      # собрать botguard и botctl в ./out
task image      # docker build -t botguard:dev .
task ci         # прогнать всё, что бегает на CI
task clean      # снести ./out и кеш-volume'ы
```

Если нужен прямой запуск без `task` — те же команды разворачиваются в
`docker run --rm -v $PWD:/src -w /src golang:1.22 <cmd>` (см. `Taskfile.yml`).

Запустить уже собранный демон с локальным конфигом:

```bash
./out/botguard -config config/botguard.yaml -log-level debug
```

Для тестирования FCrDNS без боевого Caddy: положите JSON-строки в файл,
указанный в `log.path`, демон их подхватит.

### Smoke-test без Caddy

В каталоге `dev/` лежит готовый стенд: dev-конфиг с
`caddy.reload_command: "true"` (no-op вместо admin API), упрощённый набор
правил и пять заранее заготовленных лог-строк (ChatGPT-User, SemrushBot,
PerplexityBot, AhrefsBot и обычный пользователь).

```bash
task image       # собрать botguard:dev
task dev:up      # поднять контейнер на localhost:8088
task dev:seed    # подкинуть sample-events.jsonl в access.log
task dev:check   # /healthz, /blocked, содержимое blocked.caddy
task dev:logs    # стрим JSON-логов демона
task dev:down    # остановить
task dev:reset   # обнулить БД, лог и снеппет
```

Что должно произойти после `dev:seed`:

- `/healthz` возвращает 200 OK сразу.
- `/blocked` через ~1.5 секунды возвращает JSON c четырьмя IP
  (`203.0.113.10`, `.20`, `.30`, `.40`) — это срабатывание UA-fast-path
  для on-demand AI-фетчеров и SEO-скраперов.
- `dev/work/dynamic/blocked.caddy` содержит `@botguard_bad_ip remote_ip
  203.0.113.10 203.0.113.20 …` и `respond @botguard_bad_ip 403`.
- Пятая запись (`198.51.100.7`, обычный Safari) не попадает в blocked —
  правило не нашлось, FCrDNS не запускается без правил с `require_fcrdns`.

## Версионирование

Semver-теги (`v0.1.0`, `v0.2.0`, ...). До `v1.0.0` оставляем за собой право
ломать конфиг — миграционные шаги фиксируются в `CHANGELOG.md`.

Потребителям рекомендую пинить конкретный `vX.Y.Z` в compose-файле, а не
`:latest` — это даст воспроизводимый деплой и предотвратит сюрпризы при
выкладке breaking-changes в новые мажоры.

## Лицензия

[MIT](LICENSE).
