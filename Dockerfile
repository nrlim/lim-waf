# Dockerfile for LIM WAF

# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /lim-waf -ldflags="-s -w" ./cmd/lim-waf

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary
COPY --from=builder /lim-waf /usr/local/bin/lim-waf

# Setup directories
RUN mkdir -p /etc/lim-waf/rules/custom /var/log/lim-waf

# Copy default config and rules (assumes they exist in repo)
# COPY config.yaml /etc/lim-waf/config.yaml
# COPY rules/ /etc/lim-waf/rules/

EXPOSE 80 443 9443

CMD ["lim-waf", "serve"]
