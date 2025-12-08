# Architecture

This document describes the internal architecture of CBOM-Lens.

For developer onboarding, see the [Development guide](development.md). For detector implementation details, see [Extending detectors](extending-detectors.md).

---

## 1. High-level design

CBOM-Lens is a single binary that operates in two cooperating roles when you run `cbom-lens run`:

- **Supervisor** – default process started by the user.
- **Scan** – a subprocess invoked internally as `cbom-lens _scan`.

### Supervisor responsibilities

1. Parse the `service:` configuration and initialize runtime (logging, repository, mode).
2. Set up resources based on the selected mode (manual, timer, discovery).
3. Spawn a scan as a separate subprocess (`cbom-lens _scan`).
4. Enforce single-scan execution (queue or reject concurrent scans as appropriate).
5. Collect results from the scan and handle them (print, store, upload) according to configuration.

### Scan responsibilities

- Receive scan configuration from the supervisor via stdin.
- Perform the actual scanning (filesystem, containers, ports) using configured detectors.
- Emit detections and results to stdout.
- Write errors to stderr.

The supervisor and scan communicate purely over stdin/stdout, which keeps the design portable across platforms.

---

## 2. Key packages

- `cmd/cbom-lens/`
  - CLI entrypoint, command-line parsing, wiring of detectors and configuration.

- `internal/model/`
  - Configuration models (`Config`, `Scan`) and detection types.
  - `Detection` structure:
    - Path.
    - Components (CycloneDX components).
    - Dependencies.

- `internal/scanner/`
  - Implementations of the `scan.Detector` interface for various artifact types:
    - `gitleaks` – secret detection.
    - `x509` – certificates and keys.
    - Additional detectors can be added here.

- `internal/walk/`
  - Filesystem and container image traversal.

- `internal/nmap/`
  - Integration with nmap for network port scanning.

- `internal/bom/`
  - CBOM builder, validator, and related utilities.

- `internal/service/`
  - Orchestration of scans, jobs, runners, and supervision logic.

- `internal/dscvr/`
  - Discovery server and HTTP API used in discovery mode.

---

## 3. Configuration objects

Configuration is defined in CUE (`internal/model/config.cue`) and mapped to Go structs in `internal/model`.

There are two main configuration objects:

1. **Config** (`model.Config`, CUE `#Config`)
   - Represents the full configuration for the supervisor and scan.
   - Includes service-level fields (mode, repository, server, schedule) and scan-related sections (filesystem, containers, ports).

2. **Scan** (`model.Scan`, CUE `#Scan`)
   - Represents the subset of configuration used for actual scans.
   - Focuses on scan-related fields, decoupled from long-lived supervisor settings.

The split allows:

- Treating long-lived supervisor settings as relatively static.
- Passing only scan-specific data across process boundaries and APIs.
- Reusing the same validation fragments for both full and subset configs.

---

## 4. Detector interface

Detectors encapsulate logic for discovering cryptographic assets in specific types of data.

Conceptually:

- `Detection` (from `internal/model/detection.go`) contains:
  - `Path` – where the detection came from (file, image path, etc.).
  - `Components` – list of CycloneDX components.
  - `Dependencies` – component dependencies.

- `Detector` (from `internal/scanner` or `internal/scan`) has the shape:

  ```go
  type Detector interface {
      Detect(ctx context.Context, b []byte, path string) ([]model.Detection, error)
  }
  ```

Existing detectors are wired in `cmd/cbom-lens/main.go`, for example:

- `x509.Detector{}` – certificate and key detection.
- `gitleaks.NewDetector()` – secret detection based on gitleaks rules.

See `extending-detectors.md` for how to add and register new detectors.

---

## 5. Processing flow

1. **Startup**
   - `cbom-lens run --config cbom-lens.yaml` is invoked.
   - The configuration is loaded and validated using CUE and Go structs.

2. **Supervisor setup**
   - Logging, repository, and mode-specific resources are initialized.
   - Detectors are constructed and registered.

3. **Scan execution**
   - The supervisor spawns a `_scan` subprocess.
   - Configuration relevant to the scan is sent to `_scan` via stdin.
   - `_scan` walks filesystems, images, and ports, invoking detectors.

4. **Result handling**
   - `_scan` produces a set of detections.
   - The supervisor collects detections and builds a CBOM using `internal/bom` utilities.
   - The CBOM is written to stdout, a directory, and/or uploaded to a repository.

5. **Repeat or exit**
   - In `manual` mode, the process exits after the scan.
   - In `timer` mode, the supervisor waits for the next scheduled scan.
   - In `discovery` mode, the supervisor responds to external requests from CZERTAINLY Core.

---

## 6. Performance considerations

- Some scans (e.g., large container sets or broad port ranges) can be expensive.
- Many operations are parallelized where possible (e.g., walking directories, scanning images) but are constrained to avoid overwhelming the system.
- Use `go test -short` to skip long-running tests during development.

---

## 7. Next steps

- To modify or extend detectors: see [Extending detectors](extending-detectors.md).
- To run and extend tests: see [Testing & CI](testing-ci.md).
- To adjust configuration schema: see the CUE schema [config.cue](config.cue) and the [Configuration reference](config.md).
