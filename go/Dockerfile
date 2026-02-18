# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go mod files first for better caching
COPY go/go.mod go/go.sum ./
RUN go mod download

# Copy source code
COPY go/ ./

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /coreos-tools ./cmd/coreos-tools

# Final stage - minimal image
FROM alpine:3.19

# Install CA certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Copy binary from builder
COPY --from=builder /coreos-tools /usr/local/bin/coreos-tools

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/coreos-tools"]
