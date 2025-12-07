# Overview

CBOM-Lens is a command-line tool that discovers cryptographic assets across filesystems, container images, and network ports and produces a Cryptographic Bill of Materials (CBOM) in CycloneDX 1.6 format.

It is designed to be used both as a standalone scanner and as part of the CZERTAINLY platform.

## What CBOM-Lens does

- Scans **local filesystems** for certificates, keys, and secrets.
- Scans **container images** from Docker/Podman for the same cryptographic assets.
- Scans **network ports** using nmap to detect TLS and SSH endpoints and extract their cryptographic material.
- Produces a **CycloneDX CBOM 1.6** document that inventories the discovered cryptographic assets.

## Use cases

- Building an inventory of cryptographic material across hosts, containers, and services.
- Feeding CBOMs into a **CBOM-Repository** for centralized storage and analysis.
- Integrating with **CZERTAINLY Core** to support automated cryptographic asset management.
- Supporting compliance and security programs that require visibility into certificates, keys, and cryptographic algorithms.

## Operation modes

CBOM-Lens supports three modes of operation via the `service.mode` setting:

- **Manual** – run a single scan and exit (ideal for ad-hoc scans and CI pipelines).
- **Timer** – run scans on a schedule, using cron expressions or ISO-8601 durations.
- **Discovery** – run as a service managed by CZERTAINLY via a discovery protocol.

The supervisor process and the internal `_scan` command cooperate to support these modes; see the [Architecture](architecture.md) document for details.

## Output format

The output of CBOM-Lens is a **CycloneDX 1.6 CBOM** enriched for cryptographic inventory:

- Each cryptographic asset has a stable `bom-ref` derived from its content.
- Private keys use a hash of the corresponding public key to avoid leaking private key material.
- Algorithm components use a hash of their CycloneDX JSON representation (excluding `bom-ref` and `evidence`).

See the [CBOM output format](cbom-format.md) documentation for a detailed explanation and examples.

## Integration

CBOM-Lens can:

- Save CBOM files locally (e.g., in the current directory) using the `service.dir` setting.
- Upload CBOMs to a **CBOM-Repository** using `service.repository.base_url`.
- Expose an HTTP server and integrate with **CZERTAINLY Core** in discovery mode.

For configuration details and examples, see:

- The [Configuration guide](configuration.md) – narrative configuration overview.
- The [Configuration reference](config.md) – field-by-field reference.
- [CZERTAINLY & CBOM-Repository integration](integration-czertainly.md).

## Next steps

- If you are an **operator**, start with the [Quick Start](quick-start.md).
- If you are a **security engineer**, read [Scanning use cases & best practices](scanning-use-cases.md) and [CBOM output format](cbom-format.md).
- If you are a **developer**, see the [Development guide](development.md) and [Architecture](architecture.md).
