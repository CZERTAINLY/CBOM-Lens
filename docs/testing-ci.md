# Testing & CI

This document describes how to run tests for CBOM-Lens and how they can be integrated into CI pipelines.

For developer onboarding, see the [Development guide](development.md). For architecture details, see [Architecture](architecture.md).

---

## 1. Test layout

- Unit tests are located alongside Go code under `internal/`, `cmd/`, and other packages.
- Integration tests live in `cbom-lens_test.go` at the project root.
- Test data and helper scripts are under `testing/`.

---

## 2. Running unit tests

Run all tests:

```sh
go test ./...
```

During development, use the `-short` flag to skip long-running tests:

```sh
go test -short ./...
```

Some tests (e.g., nmap scans or enumerating all Docker images) can take more time; `-short` avoids running them locally on every iteration.

---

## 3. Integration tests

Integration tests start a dedicated `cbom-lens-ci` binary and exercise it end-to-end.

### 3.1 Build the test binary

```sh
go build -race -cover -covermode=atomic -o cbom-lens-ci ./cmd/cbom-lens/
```

### 3.2 Run integration tests

```sh
go test -v
```

The integration test harness:

- Creates a temporary directory with test data.
- Runs `cbom-lens-ci` in that directory.
- Cleans up the directory after the test finishes by default.

To keep the temporary directory for further inspection, use:

```sh
go test -v -test.keepdir
```

---

## 4. Coverage and linting

You can generate coverage reports using standard Go tooling:

```sh
go test -coverprofile=coverage.out ./...
```

The repository may also include preconfigured tooling such as `golangci-lint`. To run it (if configured):

```sh
golangci-lint run
```

Check the project’s CI configuration for the exact commands and thresholds in use.

---

## 5. CI recommendations

A typical CI pipeline might include:

1. `go test -short ./...`
2. `go test -race ./...` (for race detection).
3. Integration tests with the `cbom-lens-ci` binary if resources allow.
4. Coverage and linting steps (e.g., `golangci-lint run`).

Adjust steps based on available resources and desired feedback speed.

---

## 6. Next steps

- For development workflow: see the [Development guide](development.md).
- For detector-specific tests: see [Extending detectors](extending-detectors.md).
- For more on configuration and operational behavior: see the [Configuration guide](configuration.md) and [Operations](operations.md).
