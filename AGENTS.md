# Repository Guidelines

## Project Structure & Module Organization

`botguard` is a Go 1.22 service that reads Caddy JSON access logs, resolves FCrDNS, applies allow/deny rules, stores results in SQLite, and writes a Caddy block snippet. Command entrypoints live in `cmd/botguard` for the daemon and `cmd/botctl` for the CLI. Core packages are under `internal/`: `config`, `store`, `resolver`, `rules`, `tailer`, `caddyctl`, `pipeline`, `server`, and shared `model` types. Default production examples are in `config/`; local smoke-test fixtures and generated runtime files belong under `dev/`.

## Build, Test, and Development Commands

Use `task` targets when available; they run Go tooling in pinned Docker images.

- `task test`: runs `go test -race -count=1 ./...`.
- `task lint`: runs `golangci-lint` with the repository config.
- `task fmt`: runs `gofmt -s -w` and `goimports -local github.com/postfriday/botguard`.
- `task build`: builds `out/botguard` and `out/botctl`.
- `task ci`: runs tidy, vet, lint, test, and build.
- `task image`, then `task dev:up`, `task dev:seed`, and `task dev:check`: build and exercise the local Docker smoke setup.

Without Task, use the equivalent `go test ./...`, `go vet ./...`, and `go build ./cmd/botguard ./cmd/botctl` commands.

## Coding Style & Naming Conventions

Follow `.editorconfig`: Go files use tabs; YAML, JSON, Markdown, and Taskfile content use two-space indentation. Keep Go package names short, lowercase, and aligned with existing `internal/*` package boundaries. Format imports with `goimports` using the local prefix `github.com/postfriday/botguard`. Prefer explicit error handling and context-aware APIs, matching the current daemon and HTTP code.

## Testing Guidelines

Tests use Go’s standard `testing` package and live beside implementation files as `*_test.go`. Name tests by behavior, for example `TestReloadAdminAPIPatch` or `TestRenderIdempotent`. Add table tests for parsing, normalization, and rule logic; use `httptest` for admin API interactions and `t.TempDir()` for filesystem output. Run `task test` before submitting changes.

## Commit & Pull Request Guidelines

Git history uses Conventional Commit-style prefixes such as `fix:`, `fix(ci):`, and issue or PR references like `(#123)` or `(#issue)`. Keep commits focused and describe user-visible behavior or maintenance scope. Pull requests should include a concise summary, linked issue when applicable, test results (`task ci` or the subset run), and notes for config, Docker, or Caddy behavior changes.

## Security & Configuration Tips

Do not commit generated files from `dev/work/`, local databases, credentials, or production access logs. Treat Caddy admin API URLs, basic-auth values, and resolver settings as deployment-specific configuration. Keep sample YAML safe and minimal.
