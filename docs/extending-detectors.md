# Extending Detectors

Detectors are the core abstraction for finding cryptographic assets in CBOM-Lens. This document explains how they work and how to add new ones.

For an architectural overview, see [Architecture](architecture.md). For general development workflow, see the [Development guide](development.md).

---

## 1. Detector interface

Detectors implement a common interface (simplified here):

```go
type Detector interface {
    Detect(ctx context.Context, b []byte, path string) ([]model.Detection, error)
}
```

Where:

- `ctx` – Go `context.Context` for cancellation and timeouts.
- `b` – raw bytes from the scanned source (file contents, etc.).
- `path` – logical path of the scanned item (filesystem path, image path, etc.).
- Return value – a slice of `model.Detection` objects or an error.

`Detection` (from `internal/model/detection.go`) contains:

- `Path` – where the detection was made.
- `Components` – a list of CycloneDX components describing the discovered assets.
- `Dependencies` – dependency links between components.

---

## 2. Existing detectors

CBOM-Lens ships with several built-in detectors, for example:

- `x509.Detector` – detects X.509 certificates and keys.
- Gitleaks-based detector – detects secrets (tokens, passwords, etc.) using gitleaks rules.

These are wired in `cmd/cbom-lens/main.go`, where a list of detectors is constructed and passed to the scan logic.

---

## 3. Creating a new detector

### 3.1 Implement the interface

Create a new package under `internal/scanner/` (or an appropriate subdirectory) and implement the `Detector` interface:

```go
package mydetector

import (
    "context"

    "github.com/CZERTAINLY/CBOM-Lens/internal/model"
)

type Detector struct {
    // configuration and dependencies
}

func (d *Detector) Detect(ctx context.Context, b []byte, path string) ([]model.Detection, error) {
    // Inspect b, build one or more model.Detection values, and return them.
}
```

### 3.2 Register the detector

In `cmd/cbom-lens/main.go`, add your detector to the list of detectors that are passed to the scan logic:

```go
func init() {
    // ...existing code...

    // configure default detectors
    leaks, err := gitleaks.NewDetector()
    if err != nil {
        panic(err)
    }

    detectors = []scan.Detector{
        x509.Detector{},
        leaks,
        // add your detector here, e.g.:
        // mydetector.Detector{},
    }
}
```

Ensure your new detector type satisfies the `scan.Detector` interface.

### 3.3 Add tests

- Add unit tests for your detector in the same package.
- Use fixtures under `testing/` or add new ones as needed.
- Verify that your detector produces expected components and dependencies.

---

## 4. Best practices

- **Performance** – avoid reading the same data multiple times; reuse parsed structures where possible.
- **False positives** – balance detection sensitivity with accuracy; prefer explicit rules over overly broad heuristics.
- **Error handling** – return errors only for truly exceptional conditions; skip files that are clearly not relevant without failing the entire scan.
- **Logging** – keep logging in detectors minimal and let the higher layers handle structured logging where possible.

---

## 5. Extending CBOM modeling

If your detector introduces new kinds of cryptographic assets or properties:

- Extend the modeling in `internal/bom` or related packages as appropriate.
- Ensure CBOM components follow CycloneDX 1.6 conventions.
- Add properties or `cryptoProperties` fields where needed to describe new asset types.

For examples, see how algorithms and PQC assets are modelled and described in `cbom-format.md`.

---

## 6. Next steps

- Explore existing detectors in `internal/scanner/` for concrete examples.
- Adjust configuration or schema if your detector requires new config fields (see the CUE schema [config.cue](config.cue) and the [Configuration reference](config.md)).
- Add or update documentation when new detector types or capabilities are introduced.
- For how algorithms and PQC assets are modelled in CBOMs, see [CBOM output format](cbom-format.md).
