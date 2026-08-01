########################
# Build Stage
########################
FROM golang:1.26.5-alpine3.24 AS builder

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
FROM alpine:3.24

LABEL org.opencontainers.image.authors="OmniTrust <ilm@omnitrust.com>"

# add non root user ilm
RUN apk upgrade --no-cache \
    && addgroup --system --gid 10001 ilm \
    && adduser --system --home /opt/ilm --uid 10001 --ingroup ilm ilm

COPY --from=builder /out/cbom-lens /usr/local/bin/cbom-lens

ENV LOG_LEVEL=INFO

USER 10001

ENTRYPOINT ["/usr/local/bin/cbom-lens"]
