# syntax=docker/dockerfile:1.7

FROM golang:1.23-alpine AS builder
WORKDIR /src
RUN apk add --no-cache build-base
COPY go.mod ./
RUN go mod download
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/mailprobe ./cmd/mailprobe

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata sqlite-libs
WORKDIR /app
COPY --from=builder /out/mailprobe /app/mailprobe
COPY internal/web/templates /app/internal/web/templates
COPY internal/web/static /app/internal/web/static
RUN addgroup -S app && adduser -S -G app app && mkdir -p /data && chown -R app:app /data /app
USER app
EXPOSE 8080 2525
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/app/mailprobe"]
