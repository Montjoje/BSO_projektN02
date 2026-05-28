# BSO N02 - lekki obraz kontenera zgodny z założeniami etapu I.
# Domyślnie zostawiono Go 1.26.1 zgodnie ze sprawozdaniem projektowym.
# W razie braku obrazu w rejestrze można budować z: --build-arg GO_VERSION=1.23
ARG GO_VERSION=1.26.1
FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /scanner ./cmd/scanner

FROM alpine:3.22
RUN apk add --no-cache nmap nmap-scripts ca-certificates tzdata && \
    addgroup -S scanner && adduser -S scanner -G scanner && \
    mkdir -p /app/data/scans /app/data/reports /app/data/state
WORKDIR /app
COPY --from=builder /scanner /app/scanner
COPY configs/ /app/configs/
COPY profiles/ /app/profiles/
COPY templates/ /app/templates/
COPY container/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh && chown -R scanner:scanner /app
USER scanner
ENTRYPOINT ["/app/entrypoint.sh"]
