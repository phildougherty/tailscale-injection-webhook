# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies and security updates
RUN apk add --no-cache git ca-certificates tzdata && \
    apk upgrade --no-cache

# Create non-root user for build
RUN adduser -D -g '' -u 10001 appuser

# Set working directory
WORKDIR /src

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download and verify dependencies
RUN go mod download && \
    go mod verify

# Copy source code
COPY . .

# Build arguments
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# Security scan dependencies
RUN go list -json -m all | nancy sleuth || true

# Build the binary with security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -a -installsuffix cgo \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE} -extldflags '-static'" \
    -tags 'osusergo netgo' \
    -o webhook \
    ./cmd/webhook

# Run tests
RUN go test -v -race -coverprofile=coverage.out ./...

# Final stage - use distroless for minimal attack surface
FROM gcr.io/distroless/static:nonroot

# Copy timezone data and certificates
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary with proper permissions
COPY --from=builder --chown=nonroot:nonroot /src/webhook /webhook

# Use non-root user (uid: 65532)
USER nonroot:nonroot

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/webhook", "--version"]

# Expose ports (webhook, metrics, health)
EXPOSE 8443 8080 8081

# Security configurations
ENV GOMAXPROCS=2
ENV GOGC=100

# Set entrypoint
ENTRYPOINT ["/webhook"]

# Default arguments
CMD ["--tls-min-version=1.3"]

# Metadata
LABEL org.opencontainers.image.title="Tailscale Injection Webhook"
LABEL org.opencontainers.image.description="Kubernetes admission webhook for Tailscale sidecar injection"
LABEL org.opencontainers.image.vendor="Phil Dougherty"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/phildougherty/tailscale-injection-webhook"
LABEL org.opencontainers.image.documentation="https://github.com/phildougherty/tailscale-injection-webhook/blob/main/README.md"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${COMMIT}"
LABEL org.opencontainers.image.created="${DATE}"