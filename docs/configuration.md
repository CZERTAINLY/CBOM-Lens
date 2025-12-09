# Configuration Guide

This guide explains how to configure CBOM-Lens for common deployment scenarios.

For a field-by-field reference, see the [Configuration reference](config.md). For schema details, see the CUE schema in [config.cue](config.cue).

---

## 1. Configuration basics

CBOM-Lens uses a YAML configuration file. At a high level it looks like this:

```yaml
version: 0

service:
  # runtime behavior (mode, logging, scheduling, repository, server)

filesystem:
  # filesystem scan settings

containers:
  # container scan settings

ports:
  # network port scan settings
```

Key points:

- `version` – configuration version (currently `0`).
- `service` – how CBOM-Lens runs (manual, timer, discovery) and where results go.
- `filesystem`, `containers`, `ports` – which sources to scan and how.

---

## 2. Service section

The `service` section defines how CBOM-Lens runs and handles results.

Common fields:

```yaml
service:
  mode: manual        # manual | timer | discovery
  verbose: false      # increase logging verbosity
  log: stderr         # where logs are written (stderr or file path)
  dir: .              # where to store CBOM files (optional)
  repository:
    base_url: "http://localhost:8080"  # CBOM-Repository base URL (optional)
```

### Modes

- `manual` – run one scan and exit. Used for ad-hoc scans or CI.
- `timer` – run scans repeatedly, based on `service.schedule`.
- `discovery` – run as a long-lived service managed via CZERTAINLY.

Examples:

```yaml
service:
  mode: manual
```

```yaml
service:
  mode: timer
  schedule:
    cron: "0 * * * *"  # every hour
```

```yaml
service:
  mode: timer
  schedule:
    duration: "PT15M"  # every 15 minutes
```

```yaml
service:
  mode: discovery
  repository:
    base_url: https://example.com/repo
  server:
    addr: :8080
    base_url: https://cbom-lens.example.net/api
  core:
    base_url: https://core-demo.example.net/api
```

See `scanning-modes.md` for mode semantics, cron syntax, and ISO-8601 duration details.

---

## 3. Filesystem scans

The `filesystem` section controls scanning of local directories.

```yaml
filesystem:
  enabled: true
  paths:
    - /etc/ssl
    - /var/lib/myapp
```

Notes:

- `enabled: true` turns filesystem scanning on.
- `paths` is a list of paths to scan.
  - When empty (`paths: []`), CBOM-Lens scans the current working directory.
  - Use absolute or relative paths as needed.

Use this for hosts or directories where you want to discover certificates, keys, and secrets.

---

## 4. Container scans

The `containers` section lets CBOM-Lens scan container images via Docker or Podman.

Example:

```yaml
containers:
  enabled: true
  config:
    - host: ${DOCKER_HOST}
      images:
        - docker.io/library/alpine:3.22.1
        - docker.io/library/nginx:latest
```

Notes:

- `enabled: true` turns container scanning on.
- `config` is a list of container engine configurations (e.g., multiple Docker/Podman hosts).
- Each entry typically contains:
  - `host` – how to reach the engine (can use environment variables such as `${DOCKER_HOST}`).
  - `images` – list of full image references or patterns.

Use this to scan images in registries or local engines for cryptographic materials.

---

## 5. Port scans (nmap)

The `ports` section controls network scans using **nmap**.

Minimal example:

```yaml
ports:
  enabled: true
  ipv4: true
  ipv6: false
```

Additional options (see `config-reference.md` for full details) may include:

- Which TCP ports to scan.
- Path to the nmap binary.

Notes:

- nmap must be installed and available on the target machine.
- CBOM-Lens uses nmap output to detect TLS and SSH endpoints and derive cryptographic information.

---

## 6. Saving and uploading results

Two main knobs control what happens to the generated CBOM:

- `service.dir` – if set, CBOMs are saved as `cbom-lens-<timestamp>.json` in this directory.
- `service.repository.base_url` – if set, CBOMs are uploaded to the specified CBOM-Repository.

Example:

```yaml
service:
  mode: manual
  dir: .
  repository:
    base_url: "http://localhost:8080"
```

CBOM-Lens will attempt to both save and upload. Errors in one path are logged but do not stop the other.

See `operations.md` and `integration-czertainly.md` for operational and integration details.

---

## 7. Environment variables

String values in the configuration can reference environment variables, for example:

```yaml
containers:
  enabled: true
  config:
    - host: ${DOCKER_HOST}
```

At runtime CBOM-Lens expands `${VAR}` placeholders using the current process environment.

This is useful for passing credentials, hostnames, or other dynamic values without hardcoding them in the configuration file.

See `config-reference.md` for the precise rules and examples.

---

## 8. Full example config

A full manual mode configuration example is available at:

- `examples/manual-config.yaml`

Use it as a starting point and adjust to your environment.

---

## 9. Next steps

- For exact field definitions, defaults, and constraints: see the [Configuration reference](config.md).
- For schema and validation details (CUE): see the schema file [config.cue](config.cue).
- For modes, scheduling, and discovery integration: see [Scanning modes & scheduling](scanning-modes.md) and [CZERTAINLY & CBOM-Repository integration](integration-czertainly.md).
