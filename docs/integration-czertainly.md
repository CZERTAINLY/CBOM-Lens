# CZERTAINLY & CBOM-Repository Integration

CBOM-Lens integrates with the CZERTAINLY platform and CBOM-Repository to provide centralized management of cryptographic assets.

This document explains how to configure uploads to a CBOM-Repository and how to run CBOM-Lens in discovery mode with CZERTAINLY Core.

For general configuration guidance, see the [Configuration guide](configuration.md) and [Configuration reference](config.md). For scheduling and modes, see [Scanning modes & scheduling](scanning-modes.md).

---

## 1. Uploading to CBOM-Repository

CBOM-Lens can upload generated CBOMs to a CBOM-Repository instance.

### 1.1 Basic configuration

```yaml
service:
  mode: manual
  repository:
    base_url: "http://localhost:8080"
```

Notes:

- `base_url` points to the root URL of the CBOM-Repository service.
- CBOM-Lens will attempt to upload each CBOM it generates.
- Errors are logged but do not stop CBOM-Lens from continuing other actions (such as saving to `dir`).

You can combine uploads and local file storage:

```yaml
service:
  mode: manual
  dir: .
  repository:
    base_url: "http://localhost:8080"
```

---

## 2. Discovery mode with CZERTAINLY Core

In discovery mode, CBOM-Lens runs as a long-lived service, exposing an HTTP API that CZERTAINLY Core uses to orchestrate scans.

### 2.1 Example configuration

```yaml
version: 0
service:
  mode: discovery
  repository:
    base_url: https://example.com/repo
  server:
    # where CBOM-Lens binds to; ip:port or :port
    addr: :8080
    # public address from which CBOM-Lens is accessible to CZERTAINLY
    base_url: https://cbom-lens.example.net/api
  core:
    # base address of CZERTAINLY Core API
    base_url: https://core-demo.example.net/api
```

### 2.2 Components

- **CBOM-Lens server** (`service.server`):
  - `addr` – listen address for the embedded HTTP server (e.g., `:8080`).
  - `base_url` – externally visible base URL used by CZERTAINLY Core.

- **CBOM-Repository** (`service.repository`):
  - Stores generated CBOMs for consumption by CZERTAINLY Core.
  - Strongly recommended in discovery mode, as Core typically pulls BOMs from the repository.

- **CZERTAINLY Core** (`service.core`):
  - `base_url` – endpoint of the CZERTAINLY Core API.
  - Core interacts with CBOM-Lens via discovery protocol to schedule and retrieve scans.

### 2.3 Recommended deployment pattern

- Deploy CBOM-Lens alongside a CBOM-Repository instance.
- Secure the communication paths (TLS, authentication) according to your environment’s security policies.
- Register the CBOM-Lens discovery endpoint in CZERTAINLY Core.

---

## 3. Security and networking considerations

- Ensure that `service.server.addr` and `service.server.base_url` are reachable from CZERTAINLY Core.
- Use TLS for communication between CBOM-Lens, CBOM-Repository, and CZERTAINLY Core where possible.
- Restrict access to CBOM-Lens and CBOM-Repository endpoints to trusted clients through firewall rules or access controls.

---

## 4. Troubleshooting integration

Common issues:

- **Connectivity errors** – verify URLs, DNS, and firewall rules between CBOM-Lens, CBOM-Repository, and CZERTAINLY Core.
- **Authentication failures** – if CBOM-Repository or Core require authentication, ensure credentials are configured correctly (e.g., via environment variables referenced in the config).
- **Missing BOMs in Core** – confirm that CBOM-Lens is uploading BOMs successfully and that CBOM-Repository is reachable; inspect logs on all components.

---

## 5. Next steps

- For configuration details: see the [Configuration guide](configuration.md) and [Configuration reference](config.md).
- For scan modes and scheduling: see [Scanning modes & scheduling](scanning-modes.md).
- For operational aspects and troubleshooting: see [Operations](operations.md).
