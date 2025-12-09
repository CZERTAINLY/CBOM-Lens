# CBOM-Lens

CLI tool to scan filesystems, containers, and network ports for cryptographic assets and generate a CycloneDX CBOM 1.6.

CBOM-Lens discovers certificates, keys, secrets, and algorithms across local files, container images, and services, and emits a consistent Cryptographic Bill of Materials (CBOM) that can be uploaded to a CBOM-Repository or consumed by external applications.

---

## Features

- **Multiple scan targets**
  - Local **filesystem** (certificates, keys, secrets).
  - **Container images** from Docker/Podman.
  - **Network ports** using nmap (TLS and SSH detection).
- **CycloneDX CBOM 1.6 output**
  - Stable, content-based `bom-ref` identifiers to correlate the same cryptographic assets across sources.
  - Privacy-aware handling of private keys and algorithm components.
- **Flexible operation modes**
  - One-shot **manual** runs (good for CI and ad-hoc scans).
  - **Timer** mode with cron expressions or ISO-8601 durations.
  - **Discovery** mode managed by CZERTAINLY Core.
- **Integration-ready**
  - Optional upload to a **CBOM-Repository**.
  - Designed to integrate into various applications.

For a conceptual overview and background, see the [Overview](docs/overview.md).

---

## Quick Start

### Install

Build from source (requires Go):

```sh
cd CBOM-Lens

go build -o cbom-lens ./cmd/cbom-lens
./cbom-lens --help
```

For a guided walkthrough including install and first scans, see the [Quick Start](docs/quick-start.md).

### Minimal filesystem scan

Create a config file `cbom-lens.yaml`:

```yaml
version: 0

service:
  mode: manual
  verbose: false
  log: stderr
  # Save CBOM files in the current directory; omit to print to stdout
  dir: .

filesystem:
  enabled: true
  # When empty, the current directory is scanned
  paths: []
```

Run the scan:

```sh
./cbom-lens run --config cbom-lens.yaml
```

The CBOM is written to `cbom-lens-<timestamp>.json` when `service.dir` is set, or printed to stdout otherwise.

For more filesystem, container, and port examples, see the [Quick Start](docs/quick-start.md).

---

## Configuration basics

CBOM-Lens is configured via a single YAML file. The top-level structure is:

- `version`: configuration version (currently `0`).
- `service`: runtime behavior (mode, logging, scheduling, repository, server).
- `filesystem`: filesystem scan settings.
- `containers`: container scan settings.
- `ports`: port scan settings.

Typical patterns:

- **Manual one-shot scan** – `service.mode: manual` (good for CI pipelines and ad-hoc runs).
- **Scheduled scans** – `service.mode: timer` with `service.schedule.cron` or `service.schedule.duration`.
- **CZERTAINLY-managed discovery** – `service.mode: discovery` with additional `service.server` and `service.core` configuration.

Configuration docs:

- [Configuration guide](docs/configuration.md) – narrative "how to" for common scenarios.
- [Configuration reference](docs/config.md) – field-by-field specification.
- [Configuration schema](docs/config.cue) – CUE schema used for validation.
- [Example config](docs/manual-config.yaml) – full manual-mode example you can adapt.

---

## Operation modes

CBOM-Lens supports three modes of operation, controlled by `service.mode`:

- `manual` – single scan, then exit. Best for ad-hoc runs, CI, or cron jobs managed externally.
- `timer` – CBOM-Lens stays running and executes scans on a schedule (cron or ISO-8601 duration).
- `discovery` – CBOM-Lens runs as a service managed by CZERTAINLY via the discovery protocol.

For detailed scheduling semantics (cron fields, macros such as `@daily`, and ISO-8601 durations like `P1DT2H3M4S`), see [Scanning modes & scheduling](docs/scanning-modes.md).

---

## Scanning sources

CBOM-Lens can scan three primary sources. Each has dedicated documentation:

- **Filesystem** – configure `filesystem.enabled` and `filesystem.paths` to scan directories.
  - See the [Quick Start](docs/quick-start.md#1-filesystem-scan) and the [Configuration guide](docs/configuration.md#3-filesystem-scans).
- **Container images** – configure `containers.enabled` and `containers.config` to scan images via Docker/Podman.
  - See the [Quick Start](docs/quick-start.md#2-container-image-scan-docker--podman) and the [Configuration guide](docs/configuration.md#4-container-scans).
- **Network ports (nmap)** – configure `ports.enabled` and related fields to scan ports.
  - See the [Quick Start](docs/quick-start.md#3-port-scan-nmap) and the [Configuration guide](docs/configuration.md#5-port-scans-nmap).

For broader strategies and best practices, see [Scanning use cases & best practices](docs/scanning-use-cases.md).

---

## Saving and uploading results

By default, CBOM-Lens prints the generated CBOM to standard output.

You can also:

- Save CBOMs to files using `service.dir`.
- Upload CBOMs to a CBOM-Repository using `service.repository.base_url`.

For operational details and examples, see:

- [Operations](docs/operations.md) – running, logging, output handling.
- [CZERTAINLY & CBOM-Repository integration](docs/integration-czertainly.md).

CBOM format details (including `bom-ref` strategy and PQC modelling) are documented in [CBOM output format](docs/cbom-format.md).

---

## Development

If you want to understand or extend CBOM-Lens:

- [Development guide](docs/development.md) – environment, build, and workflow.
- [Architecture](docs/architecture.md) – internal design and package layout.
- [Extending detectors](docs/extending-detectors.md) – how to add new scan detectors.
- [Testing & CI](docs/testing-ci.md) – running unit and integration tests.

---

## Post-Quantum Cryptography support

CBOM-Lens can detect certain Post-Quantum Cryptography (PQC) algorithms in artifacts even though Go’s standard library does not yet implement them.

- Detection support exists for the **ML-DS** family.
- PQC algorithms are modelled as cryptographic algorithm assets with detailed properties (key sizes, signature sizes, security levels, etc.).

For examples of how PQC algorithms are represented in CBOMs, see [CBOM output format](docs/cbom-format.md).

---

## License

CBOM-Lens is licensed under the terms specified in [LICENSE.md](LICENSE.md).
