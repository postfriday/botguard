# syntax=docker/dockerfile:1.7

# ─────────────────────────────────────────────────────────────────────────────
# Build stage
# ─────────────────────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS build

WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath

# Copy source. We don't pre-copy go.mod for caching because go.sum may not
# exist on first build and Docker's wildcard semantics for an absent file
# differ between the classic builder and BuildKit.
COPY . .

# `go mod tidy` materialises go.sum on first build, after which subsequent
# builds reuse the module cache layer.
RUN go mod tidy \
 && go build -ldflags="-s -w" -o /out/botguard ./cmd/botguard \
 && go build -ldflags="-s -w" -o /out/botctl   ./cmd/botctl

# ─────────────────────────────────────────────────────────────────────────────
# Runtime stage
# ─────────────────────────────────────────────────────────────────────────────
FROM alpine:3.20 AS production

RUN apk add --no-cache ca-certificates tzdata curl procps

COPY --from=build /out/botguard /usr/local/bin/botguard
COPY --from=build /out/botctl   /usr/local/bin/botctl

# Default config & rules baked in; mount overrides at /etc/botguard
COPY config/botguard.yaml /etc/botguard/botguard.yaml
COPY config/rules.yaml    /etc/botguard/rules.yaml

RUN mkdir -p /var/lib/botguard /var/log/caddy /etc/caddy/dynamic

# Runs as root inside the container so it can write to /etc/caddy/dynamic
# and read /var/log/caddy — both volumes are initialised by the caddy image
# (which also runs as root). The container is the security boundary; root
# inside it does NOT mean root on the host.

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD pgrep -x botguard >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/botguard"]
CMD ["-config", "/etc/botguard/botguard.yaml", "-log-level", "info"]
