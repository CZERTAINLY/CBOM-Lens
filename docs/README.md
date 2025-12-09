# CBOM-Lens Documentation

CBOM-Lens is a CLI tool that scans filesystems, container images, and network ports to discover cryptographic assets and produces a CycloneDX CBOM 1.6. This directory contains operator, security, and developer documentation.

---

## Start here

- **Project overview:** see the top-level [README](../README.md) and [Overview](overview.md).
- **Quick start (operators):** [Quick Start](quick-start.md).
- **Configuration guide:** [Configuration guide](configuration.md).
- **Scan modes & scheduling:** [Scanning modes & scheduling](scanning-modes.md).

---

## Operator documentation

- [Overview](overview.md) – product overview and key concepts.
- [Quick Start](quick-start.md) – minimal examples for filesystem, container, and port scans.
- [Configuration guide](configuration.md) – narrative configuration guide with practical examples.
- [Scanning modes & scheduling](scanning-modes.md) – manual, timer, and discovery modes; cron and ISO-8601 schedules.
- [Operations](operations.md) – running CBOM-Lens in practice (logs, outputs, uploads).
- [CZERTAINLY & CBOM-Repository integration](integration-czertainly.md) – integrating with CZERTAINLY Core and CBOM-Repository.

---

## Security & CBOM documentation

- [Scanning use cases & best practices](scanning-use-cases.md) – scanning strategies and best practices for security teams.
- [CBOM output format](cbom-format.md) – CBOM structure, `bom-ref` semantics, and PQC representation.

---

## Configuration & reference

- [Configuration guide](configuration.md) – how to configure CBOM-Lens for common deployment scenarios.
- [Configuration reference](config.md) – field-by-field configuration reference.
- [Example manual mode configuration](manual-config.yaml) – full manual mode configuration example.
- [CUE configuration schema](../internal/model/config.cue) – formal configuration schema used for validation.

---

## Developer documentation

- [Development guide](development.md) – developer onboarding, build, and workflow.
- [Architecture](architecture.md) – architecture, processes, and package layout.
- [Extending detectors](extending-detectors.md) – how to implement and wire new detectors.
- [Testing & CI](testing-ci.md) – tests, integration tests, and CI setup.

---

## See also

- Top-level project [README](../README.md) for a concise overview and quick start.
- [LICENSE.md](../LICENSE.md) for license information.
