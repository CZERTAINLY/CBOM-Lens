# Quick Start

This guide shows how to run CBOM-Lens as quickly as possible for the most common scenarios.

For a conceptual overview, see the [Overview](overview.md). For a full configuration guide, see the [Configuration guide](configuration.md).

---

## 1. Filesystem scan

### Example configuration

Create `cbom-lens.yaml`:

```yaml
version: 0

service:
  mode: manual
  verbose: false
  log: stderr
  # Save CBOM files in the current directory
  dir: .

filesystem:
  enabled: true
  # Empty list means "scan the current working directory"
  paths: []
```

### Run the scan

```sh
./cbom-lens run --config cbom-lens.yaml
```

You should see logs similar to:

```text
{"time":"2025-10-10T14:14:04.632066182+02:00","level":"WARN","msg":"command has no timeout","path":"usr/bin/cbom-lens","cbom-lens":{"cmd":"run","pid":2488398}}
{"time":"2025-10-10T14:14:05.410539638+02:00","level":"INFO","msg":"bom saved","path":"cbom-lens-2025-10-10-02:14:05.json","cbom-lens":{"cmd":"run","pid":2488398}}
```

The CBOM will be saved as `cbom-lens-<timestamp>.json` in the current directory.

---

## 2. Container image scan (Docker / Podman)

### Prerequisites

- Docker or Podman installed.
- Optional: `DOCKER_HOST` or equivalent environment variable set to reach your engine.

### Example configuration

```yaml
version: 0

service:
  mode: manual
  verbose: false
  log: stderr
  dir: .

containers:
  enabled: true
  config:
    - host: ${DOCKER_HOST}
      images:
        - docker.io/library/alpine:3.22.1
```

### Run the scan

```sh
./cbom-lens run --config cbom-lens.yaml
```

CBOM-Lens will pull and inspect the specified image(s), then produce a CBOM with discovered cryptographic assets.

For more container configuration options, see the [Configuration guide](configuration.md#4-container-scans).

---

## 3. Port scan (nmap)

### Prerequisites

- `nmap` installed and available on `PATH`.

### Example configuration

```yaml
version: 0

service:
  mode: manual
  dir: .

ports:
  enabled: true
  ipv4: true
  ipv6: false
  # Additional options such as ports and nmap binary can be configured; see configuration docs.
```

### Run the scan

```sh
./cbom-lens run --config cbom-lens.yaml
```

CBOM-Lens invokes nmap to discover TLS and SSH services, extracts cryptographic details, and emits a CBOM.

For more port scan configuration options, see the [Configuration guide](configuration.md#5-port-scans-nmap).

---

## 4. Where results go

- **Default** – CBOM is printed to stdout.
- **File output** – set `service.dir` to save files as `cbom-lens-<timestamp>.json`.
- **Repository upload** – configure `service.repository.base_url` to upload results to a CBOM-Repository instance.

Example:

```yaml
service:
  mode: manual
  dir: .
  repository:
    base_url: "http://localhost:8080"
```

CBOM-Lens will attempt to both save locally and upload; failures in one method do not prevent the other.

For more operational details, see [Operations](operations.md).

---

## 5. Next steps

- Learn how to adjust configuration for real deployments: see the [Configuration guide](configuration.md).
- Understand all available fields: see the [Configuration reference](config.md).
- Learn about modes and scheduling (timer, discovery): see [Scanning modes & scheduling](scanning-modes.md).
- Integrate with CZERTAINLY and CBOM-Repository: see [CZERTAINLY & CBOM-Repository integration](integration-czertainly.md).
