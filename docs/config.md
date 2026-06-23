# Configuration Reference

This document is the field-by-field reference for the CBOM-Lens configuration.

For a narrative configuration guide, see the [Configuration guide](configuration.md). For CUE schema details, see the schema file [config.cue](config.cue).

---

# CBOM-Lens Configuration Schema

Note the [config.cue](config.cue) enables slightly more options, however those are those, which are supported now.

An example is in [manual-config.yaml](manual-config.yaml).

# Top-level object:
- `version` (required, number, fixed `0`)
- `service` (required, [Service](#service) section)
- `filesystem` (optional, [Filesystem](#filesystem) section)
- `containers` (optional, [ContainerConfig](#containerconfig))
- `ports` (optional, [Ports](#ports) section)
- `registry` (optional, [Registry](#registry) section)

## Service
Service:
- `mode` (string, required, default "manual")
- `verbose` (bool, optional, default false) Extra logging.
- `dir` (string, optional) Local results directory. Results will be printed to standard output.

## Filesystem:

Configure filesystem scan. Following modules are used

 * (x509) certificates
 * secrets

- `enabled` (bool, default false) Enable filesystem scanning.
- `paths` (list of string, optional, default: if unset directory of a configuration file) paths to scan. If path is not accessible Warning is printed to logs.

> [!NOTE]
> If `filesystem.enabled` is false (or omitted) no filesystem paths are processed.

### Path resolution

Relative paths are resolved against the directory of the configuration file; absolute paths remain unchanged.

Example input:
```yaml
filesystem:
  enabled: true
  paths:
    - /absolute
    - relative
```

Command:
```
cbom-lens run --config /tmp/config.yaml
```

Resolved paths:
- `/absolute`
- `/tmp/relative`

## Containers:

This section configures a Docker and other compatible container engine scan.

- `enabled` (bool, default false) Turn containers scanning off.
- `config` list of the engines to scan

## Engine configuration

- `name` (string, optional), friendly human name
- `type`: (empty, "docker", "podman", optional) is an engine type. Defaults to docker
- `host`: (string, required) socket path or endpoint to container engine. May reference an environment variable like `${DOCKER_HOST}`.
- images (list of string, optional) Explicit image names or patterns to include. Empty / omitted means discover all.

## Ports

- `enabled` (bool, optional, default false) Enable local port scanning.
- `binary` (string, optional) Path to nmap binary; falls back to PATH lookup.
- `ports` (string, optional, default "1-65535") Comma/range expression (e.g. `22,80,443,8000-8100`).
- `ipv4` (bool, optional, default true) Scan IPv4.
- `ipv6` (bool, optional, default true) Scan IPv6.

## Registry

Windows Registry scanning. Enabling this on non-Windows platforms produces an error. See the [Windows Registry scanning](registry-scanning.md) guide for usage examples.

- `enabled` (bool, default false) Enable registry scanning.
- `paths` (list of RegistryPath) Registry locations to scan. When empty, defaults to the `HKLM` and `HKCU` hive roots.
- `max_depth` (int, default 0) Maximum subkey recursion depth. `0` = unlimited.
- `max_value_size` (int, default 1048576) Skip values larger than this (bytes).
- `wow64` (bool, default false) Scan both 64-bit and 32-bit registry views.
- `include` (RegistryFilter) Only process keys/values matching these regex patterns.
- `exclude` (RegistryFilter) Skip keys/values matching these regex patterns.

### RegistryPath

- `hive` (string, required) One of `HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`.
- `key` (string, optional) Subkey path relative to the hive root. Omitted or empty scans the entire hive.

### RegistryFilter

- `keys` (list of string) Regex patterns matched against key paths.
- `values` (list of string) Regex patterns matched against value names.

## Service

- `verbose` (bool, optional) - produce debug logs or not
- `mode` (string, optional), mode of a service. Can be `manual`, `timer` or `discovery`

### Manual mode
- Description: No automatic scheduling or discovery; actions are performed manually.
- Optional fields that may still be present:
  - `dir` (string) — where to store the CBOM.
  - `repository` (#Repository) — CBOM-Repository configuration associated with the service.

### Timer mode
- Description: Service runs on a schedule.
- Required when `mode` is `timer`:
  - `schedule` (type: #Schedule) — schedule specification for running the service.
- `schedule.cron` expects the configuration in 5 fields cron format, however
  macros like @daily, @weekly or @every Go time.Duration are allowed too.
- `schedule.duration` expects data as ISO-8601 format
- Optional fields that may still be present:
  - `dir` (string) — where to store the CBOM.
  - `repository` (#Repository) — CBOM-Repository configuration associated with the service.

### Discovery mode
- Description: Service is created via discovery and must include runtime server configurations.
- Required when `mode` is `discovery`:
  - `server` (#Server) — cbom-lens server configuration (required, not null).
  - `core` (#Core) — CZERTAINLY core configuration (required, not null).
  - `repository` (#Repository)
- Optional fields that may still be present:
  - `dir` (string)


### Repository
- Type: object (#Repository)
- Description: Configuration for an external repository used by the service.
- Fields:
  - `base_url` (required, type: #URL) — the repository's base URL. This is the canonical location used to fetch artifacts/configuration. See the #URL definition for allowed formats and validation rules.

## Environment variables

Every string item can contain the environment variable, which will be expanded.
So this is legal configuration.

```yaml
repository:
  base_url: ${CBOM_REPOSITORY_BASE_URL}
```
