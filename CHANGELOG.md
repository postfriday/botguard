# Changelog

Все заметные изменения этого проекта документируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
проект придерживается [Semantic Versioning](https://semver.org/lang/ru/).

## [Unreleased]

### Added
- Перенос проекта в самостоятельный репозиторий (`github.com/postfriday/botguard`).
- Корневой `Dockerfile` с multi-stage сборкой (`golang:1.22-alpine` → `alpine:3.20`).
- Базовый CI на GitHub Actions: `test`, `lint`, multi-arch `build-image`.
- `LICENSE` (MIT) и `CHANGELOG.md`.
- `Taskfile.yml` с командами для запуска всех Go-операций (tidy/vet/lint/test/build)
  внутри docker-контейнера `golang:1.22` с named-volume'ами под кеши.
- Каталог `dev/` со стендом для smoke-теста без Caddy (dev-конфиг,
  упрощённые правила, sample-events.jsonl) и task-цели `dev:up`,
  `dev:seed`, `dev:check`, `dev:logs`, `dev:down`, `dev:reset`.

### Changed
- Module path: `github.com/selardo/botguard` → `github.com/postfriday/botguard`.
- CI: апгрейд actions до Node 24-совместимых версий
  (`actions/checkout@v5`, `actions/setup-go@v6`, `golangci/golangci-lint-action@v8`).
- Линтер: миграция с golangci-lint v1.59 на v2.12 — `.golangci.yml` переписан
  на v2-схему (`formatters` отдельной секцией, `gosimple` слит в `staticcheck`).
- README переписан под отдельный проект (без selardo-зависимостей).
- Caddyfile больше не запекается в образ — потребитель монтирует свой
  `/etc/caddy/Caddyfile` read-only.
- Сниппет `blocked.caddy` теперь содержит нейтральный комментарий вместо
  упоминания конкретного домена.

### Removed
- COPY `.docker/caddy/etc/Caddyfile.production` из Dockerfile.
- Selardo-специфичные ссылки в комментариях кода и в README.
