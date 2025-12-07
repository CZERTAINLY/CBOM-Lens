# CBOM-Lens Documentation
- `LICENSE.md` for license information.
- Top-level project `README.md` for a concise overview and quick start.

## See also

- `testing-ci.md` – tests, integration tests, and CI setup.
- `extending-detectors.md` – how to implement and wire new detectors.
- `architecture.md` – architecture, processes, and package layout.
- `development.md` – developer onboarding, build, and workflow.

## Developer documentation

- `examples/manual-config.yaml` – full manual mode configuration example.
- `config-schema.md` – CUE schema overview and validation rules.
- `config-reference.md` – field-by-field configuration reference.

## Configuration & reference

- `cbom-format.md` – CBOM structure, `bom-ref` semantics, and PQC representation.
- `scanning-use-cases.md` – scanning strategies and best practices for security teams.

## Security & CBOM documentation

- `integration-czertainly.md` – integrating with CZERTAINLY Core and CBOM-Repository.
- `operations.md` – running CBOM-Lens in practice (logs, outputs, uploads).
- `scanning-modes.md` – manual, timer, and discovery modes; cron and ISO-8601 schedules.
- `configuration.md` – narrative configuration guide with practical examples.
- `quick-start.md` – minimal examples for filesystem, container, and port scans.
- `installation.md` – how to install and upgrade CBOM-Lens.
- `overview.md` – product overview and key concepts.

## Operator documentation

- **Scan modes & scheduling:** `docs/scanning-modes.md`.
- **Configuration guide:** `docs/configuration.md`.
- **Quick start (operators):** `docs/quick-start.md`.
- **Project overview:** see the top-level `README.md` and `docs/overview.md`.

## Start here

- **Developers / contributors** – understanding the architecture, extending detectors, and running tests.
- **Security engineers** – understanding what is scanned, what the CBOM contains, and how to use it.
- **Operators / DevOps** – installing, configuring, and running CBOM-Lens.

## Audience guide

CBOM-Lens is a CLI tool that scans filesystems, container images, and network ports to discover cryptographic assets and produces a CycloneDX CBOM 1.6. This directory contains operator, security, and developer documentation.

Welcome to the CBOM-Lens documentation.


