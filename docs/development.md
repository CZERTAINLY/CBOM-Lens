# Development Guide

This document helps developers and contributors get started working on CBOM-Lens.

For detailed architecture information, see [Architecture](architecture.md). For testing, see [Testing & CI](testing-ci.md).

---

## 1. Prerequisites

- Go toolchain (see `go.mod` for the minimum supported version).
- Git.
- Optional but recommended:
  - Docker or Podman – to run container-related tests.
  - nmap – to run port scan tests.
  - golangci-lint – for linting.

---

## 2. Getting the source

Clone the repository:

```sh
git clone https://github.com/CZERTAINLY/CBOM-Lens.git
cd CBOM-Lens
```

---

## 3. Building

Build the main binary:

```sh
go build -o cbom-lens ./cmd/cbom-lens
```

Run it:

```sh
./cbom-lens --help
```

For integration tests, a special binary `cbom-lens-ci` is used; see `testing-ci.md`.

---

## 4. Project layout

Key directories:

- `cmd/cbom-lens/` – CLI entrypoint and wiring of detectors.
- `internal/bom/` – CBOM builder and validation logic.
- `internal/cdxprops/` – CycloneDX property helpers and algorithms.
- `internal/model/` – configuration, detection, and domain models.
- `internal/dscvr/` – discovery server and related APIs.
- `internal/service/` – service orchestration, jobs, and runners.
- `internal/walk/` – filesystem and image walking.
- `internal/nmap/` – integration with nmap.
- `internal/scanner/` – detectors such as gitleaks and x509.
- `docs/` – user and developer documentation.
- `testing/` – supporting scripts and test data for integration tests.

See `architecture.md` for more details.

---

## 5. Coding guidelines

- Follow idiomatic Go style (`gofmt`, `go vet`).
- Use structured logging consistently.
- Handle errors explicitly and propagate them with context.
- Keep public APIs stable; prefer adding new functions over changing existing signatures.

If you add new configuration fields:

- Update the Go structs in `internal/model`.
- Update the CUE schema in `docs/config.cue`.
- Extend `config-reference.md` with the new field.

---

## 6. Running tests

See `testing-ci.md` for detailed instructions.

Typical commands:

```sh
go test ./...
```

Use the `-short` flag during development to skip long-running tests:

```sh
go test -short ./...
```

---

## 7. Contributing

If you plan to contribute:

- Open an issue or discussion describing the change you plan to make.
- Follow the existing code style and patterns in the repository.
- Add tests for new features or bug fixes.
- Update documentation where relevant.

If a `CONTRIBUTING.md` file is present in the repository, follow the guidelines described there.

---

## 8. Next steps

- Understand the internal design: see [Architecture](architecture.md).
- Learn how to build new detectors: see [Extending detectors](extending-detectors.md).
- Set up and run tests: see [Testing & CI](testing-ci.md).
