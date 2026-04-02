# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /workspace

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /aegis-operator \
    ./cmd/operator/

# Runtime stage
FROM gcr.io/distroless/static:nonroot

WORKDIR /
COPY --from=builder /aegis-operator .

USER 65532:65532

ENTRYPOINT ["/aegis-operator"]
