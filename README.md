# CBOM-Lens

CLI tool to scan filesystems, containers, and network ports for cryptographic assets and generate a CycloneDX CBOM 1.6 or 1.7.

CBOM-Lens discovers certificates, keys, secrets, and algorithms across local files, container images, and services, and emits a consistent Cryptographic Bill of Materials (CBOM) that can be uploaded to a CBOM-Repository or consumed by external applications.

---

## Why CBOM-Lens

**The first CBOM producer to emit the CycloneDX 1.7 cryptography registry.**
1.7 added two registry-backed fields to `algorithmProperties`, `algorithmFamily`
and `ellipticCurve`, and CBOM-Lens is — as far as we can establish — the first
tool to actually write them. As of 2026-07-30 `cdxgen` defaults to 1.7 and emits
neither; `cyclonedx-cli` and the Python, JavaScript and .NET libraries drop both
when converting; the reference `cyclonedx-core-java` only gained the capability
in 13.0.0. That claim is dated and falsifiable on purpose: **find a producer that
got there first and we will correct it.**

**Post-quantum algorithms are detected, not guessed.** ML-DSA (FIPS 204),
SLH-DSA (FIPS 205, all 12 parameter sets), ML-KEM (FIPS 203), XMSS, XMSS-MT and
HSS-LMS are recognised from their OIDs and modelled with key sizes, signature
sizes and NIST security categories transcribed from the standards, each with its
citation recorded next to the value in the source. Where no authoritative source
exists, the field is **omitted rather than invented** — stateful hash-based
signatures carry no `nistQuantumSecurityLevel` because SP 800-208 assigns them
none, and HQC and FN-DSA are not claimed at all because no OID has been assigned
to them.

**A wrong answer is treated as worse than no answer.** Both registry fields are
closed enumerations — 93 families, 246 curves — where a single out-of-vocabulary
value invalidates the entire document, so CBOM-Lens maps through total tables and
omits on a miss instead of passing a string through. Curves that could only be
guessed, such as one inferred from a signature digest or borrowed from a
different certificate on the same port, are deliberately left unmapped. The
vendored schema snapshot means validation runs fully offline.

Details in [CycloneDX 1.7 cryptography registry](#cyclonedx-17-cryptography-registry)
and [PQC support](docs/pqc-support.md).

---

## Features

- **Multiple scan targets**
  - Local **filesystem** (certificates, keys, secrets).
  - **Container images** from Docker/Podman.
  - **Network ports** using nmap (TLS and SSH detection).
- **CycloneDX CBOM 1.6 and 1.7 output**
  - Stable, content-based `bom-ref` identifiers to correlate the same cryptographic assets across sources.
  - Privacy-aware handling of private keys and algorithm components.
  - **First known producer to emit the 1.7 cryptography registry fields** `algorithmFamily` and `ellipticCurve` — see below.
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
- `cbom`: CBOM output settings, including `version` (`"1.6"` default, or `"1.7"`).

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

## CycloneDX 1.7 cryptography registry

CycloneDX 1.7 added two registry-backed fields to `algorithmProperties`:
`algorithmFamily` and `ellipticCurve`. Both are **closed enumerations** — 93
permitted families, 246 curves, every curve namespaced like `secg/secp256r1`.
One value outside the enum makes the whole document fail schema validation.

**CBOM-Lens is the first known CBOM producer to emit them.** As of 2026-07-30,
`cdxgen` defaults to 1.7 and writes neither field; `cyclonedx-cli` and the
Python, JavaScript, and .NET libraries drop both silently when converting; and
the reference `cyclonedx-core-java` gained the capability only in 13.0.0. If you
find a producer that got there first, open an issue and we will correct this.

How it is kept honest:

- **Total mapping tables, no passthrough.** A value is emitted only when it maps
  to a registry member. Anything unrecognised is omitted rather than guessed,
  because a plausible-looking wrong curve is worse than a missing one.
- **Only trustworthy sources map.** Curves inferred from a signature's digest,
  or resolved from a different certificate on the same port, are deliberately
  left unmapped — they are guesses, and a CBOM should not assert a guess.
- **The enum is vendored and pinned.** The registry is a living document served
  from an unversioned URL, so the schema snapshot is committed and every table
  value is checked against it by test. Validation runs fully offline.

Set `cbom.version: "1.7"` in the config file to select 1.7 output; `"1.6"`
remains the default and stays the compatibility format. In 1.7 output the
superseded reference fields (`signatureAlgorithmRef`, `subjectPublicKeyRef`,
`algorithmRef`, `cryptoRefArray`) are **cleared** in favour of
`relatedCryptographicAssets`, which cannot carry a dangling reference. The one
field emitted twice is `curve`, kept alongside `ellipticCurve` because 1.7
deprecates it by annotation only and most consumers still read it.

---

## Post-Quantum Cryptography support

CBOM-Lens detects Post-Quantum Cryptography (PQC) algorithms in artifacts even
though Go's standard library does not yet implement most of them.

- **ML-DSA** (FIPS 204), **SLH-DSA** (FIPS 205, all 12 parameter sets),
  **ML-KEM** (FIPS 203), **XMSS**, **XMSS-MT**, and **HSS-LMS**.
- Modelled as cryptographic algorithm assets with key sizes, signature sizes,
  and NIST security categories transcribed from the standards, with the citation
  recorded next to each value.
- Values with no authoritative source are **omitted, not invented**. Stateful
  hash signatures carry no `nistQuantumSecurityLevel`, because SP 800-208
  assigns them no NIST category. HQC and FN-DSA are not detected at all: FIPS
  206 and 207 are unpublished, so no assigned OID exists to match.

For examples of how PQC algorithms are represented in CBOMs, see
[CBOM output format](docs/cbom-format.md) and [PQC support](docs/pqc-support.md).

---

## License

CBOM-Lens is licensed under the terms specified in [LICENSE.md](LICENSE.md).
