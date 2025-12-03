########################
# Build Stage
########################
FROM golang:1.25-alpine3.22 AS builder

ARG VERSION=dev
ENV CGO_ENABLED=0 \
    GOFLAGS="-trimpath" \
    LDFLAGS="-s -w -X main.version=${VERSION}"

WORKDIR /src

# Better layer caching for deps
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

# Copy the rest and build
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags "${LDFLAGS}" -o /out/cbom-lens ./cmd/cbom-lens

########################
# Run Stage
########################
FROM alpine:3.23

LABEL org.opencontainers.image.authors="CZERTAINLY <support@czertainly.com>"

# add non root user czertainly
RUN addgroup --system --gid 10001 czertainly && adduser --system --home /opt/czertainly --uid 10001 --ingroup czertainly czertainly

COPY --from=builder /out/cbom-lens /usr/local/bin/cbom-lens

ENV LOG_LEVEL=INFO

USER 10001

ENTRYPOINT ["/usr/local/bin/cbom-lens"]
