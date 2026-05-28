FROM golang:1.26.1-alpine AS builder
WORKDIR /app
COPY go.mod .
COPY cmd/ /app/cmd/
COPY internal/ /app/internal/
RUN CGO_ENABLED=0 GOOS=linux go build -o /scanner ./cmd/scanner

FROM alpine:3.22
RUN apk add --no-cache nmap bash ca-certificates
WORKDIR /app
COPY configs/ /app/configs/
COPY profiles/ /app/profiles/
COPY templates/ /app/templates/
COPY container/entrypoint.sh /app/entrypoint.sh
COPY --from=builder /scanner /app/scanner
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
