# Stage 1: Build the statically linked Go binary
FROM golang:1.24-alpine AS builder

WORKDIR /src
ENV GOTOOLCHAIN=auto

RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o /app/registry ./cmd/registry

# Stage 2: Hardened runtime image
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata
# Create a dedicated non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy binary only (migrations are embedded inside the binary via go:embed)
COPY --from=builder /app/registry /app/registry
RUN chown -R appuser:appgroup /app

USER appuser
EXPOSE 8080

ENTRYPOINT ["/app/registry"]
