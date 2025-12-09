# Operations

This document covers how to run CBOM-Lens in practice: logging, outputs, uploads, and operational tips.

For configuration details, see the [Configuration guide](configuration.md) and the [Configuration reference](config.md).

---

## 1. Running the CLI

The main entrypoint is the `run` command:

```sh
./cbom-lens run --config cbom-lens.yaml
```

Key points:

- `--config` points to the YAML configuration file.
- The `service.mode` in the configuration determines whether CBOM-Lens runs once (`manual`) or stays running (`timer`, `discovery`).
- The internal `_scan` subcommand is used by the supervisor and is not normally invoked directly by users.

---

## 2. Logging

Logging is controlled by the `service` section:

```yaml
service:
  verbose: false
  log: stderr
```

- `verbose: true` increases log detail (useful while debugging).
- `log` controls where logs go:
  - `stderr` – default, human- and machine-readable JSON logs on standard error.
  - File path – write logs to a file.

Log entries include timestamps, log level, message, and command context, for example:

```text
{"time":"2025-10-10T14:14:05.410539638+02:00","level":"INFO","msg":"bom saved","path":"cbom-lens-2025-10-10-02:14:05.json","cbom-lens":{"cmd":"run","pid":2488398}}
```

---

## 3. Output management

### 3.1 Standard output

By default, CBOM-Lens prints the generated CBOM to **stdout**.

This is useful when integrating with other tools via pipelines or capturing the output in CI.

### 3.2 Saving to files

To save CBOMs to files, set `service.dir`:

```yaml
service:
  mode: manual
  dir: .
```

- CBOM-Lens will write CBOMs as `cbom-lens-<timestamp>.json` into the specified directory.
- The timestamp includes date and time, making filenames unique and sortable.

### 3.3 Uploading to a CBOM-Repository

To automatically upload CBOMs to a CBOM-Repository, configure:

```yaml
service:
  mode: manual
  repository:
    base_url: "http://localhost:8080"
```

- CBOM-Lens will POST CBOMs to the repository.
- Errors during upload are logged.

### 3.4 Combining file output and uploads

You may configure both `dir` and `repository`:

```yaml
service:
  mode: manual
  dir: .
  repository:
    base_url: "http://localhost:8080"
```

CBOM-Lens will:

1. Save the CBOM to the specified directory.
2. Attempt to upload the same CBOM to the repository.

Failures in one path are logged but do not prevent the other from being attempted.

---

## 4. Long-running scans and timeouts

Some scans may take a long time, for example when scanning many images or performing large nmap sweeps.

- CBOM-Lens may log a warning like:

  ```text
  {"level":"WARN","msg":"command has no timeout", ...}
  ```

  indicating that an underlying command (such as nmap) is not time-limited.

Operational tips:

- Prefer narrower scopes (specific directories, images, or port ranges) for regular scans.
- Adjust external orchestrators (e.g., CI, systemd, Kubernetes) to enforce global timeouts when necessary.

---

## 5. Deployment scenarios

Common deployment patterns:

- **Local manual runs** – run CBOM-Lens locally against a directory or a small set of images; collect CBOMs manually or via scripts.
- **CI integration** – run in `manual` mode, scanning source trees or build artifacts and publishing CBOMs as build artifacts or to a repository.
- **Scheduled host scans** – run in `timer` mode on servers or scanners to periodically scan files, containers, or ports.
- **Managed discovery** – run in `discovery` mode as part of a CZERTAINLY deployment; see `integration-czertainly.md`.

---

## 6. Troubleshooting

- **No CBOM output** – ensure `filesystem.enabled`, `containers.enabled`, or `ports.enabled` are set correctly and the target paths/engines are reachable.
- **Permission errors** – run CBOM-Lens with sufficient privileges to read files, talk to container engines, or perform network scans.
- **nmap not found** – install nmap and ensure it is on `PATH`, or configure the binary path if supported.
- **Repository upload failures** – verify `service.repository.base_url`, network connectivity, and repository logs.

If issues persist, increase verbosity (`service.verbose: true`) and inspect logs for detailed error messages.

---

## 7. Next steps

- Learn about scan modes and schedules: see [Scanning modes & scheduling](scanning-modes.md).
- Configure repository and CZERTAINLY integration: see [CZERTAINLY & CBOM-Repository integration](integration-czertainly.md).
- See test and CI guidance: see [Testing & CI](testing-ci.md).
