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

### Changed
- Module path: `github.com/selardo/botguard` → `github.com/postfriday/botguard`.
- README переписан под отдельный проект (без selardo-зависимостей).
- Caddyfile больше не запекается в образ — потребитель монтирует свой
  `/etc/caddy/Caddyfile` read-only.
- Сниппет `blocked.caddy` теперь содержит нейтральный комментарий вместо
  упоминания конкретного домена.

### Removed
- COPY `.docker/caddy/etc/Caddyfile.production` из Dockerfile.
- Selardo-специфичные ссылки в комментариях кода и в README.
