# Windows Registry Scanning

CBOM-Lens can scan the Windows Registry for cryptographic materials stored as registry values (certificates, keys, PEM blobs). This is useful on Windows hosts where applications store TLS certificates or private keys in the registry rather than the filesystem.

On non-Windows platforms the registry scanner returns an error when enabled, because the Windows registry is not available.

---

## Quick start

```yaml
version: 0
service:
  mode: manual
registry:
  enabled: true
  paths:
    - hive: HKLM
      key: 'SOFTWARE\Microsoft\SystemCertificates'
```

This scans `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` and all subkeys for values that contain cryptographic material.

When `paths` is omitted, the scanner targets the well-known Windows crypto subtrees under both the machine-wide (`HKLM`) and current-user (`HKCU`) hives — so enabling the scanner with no further configuration scans the certificate stores and cryptography configuration:

```yaml
registry:
  enabled: true
```

The zero-config default expands to:

| Hive | Key |
|------|-----|
| `HKLM` | `SOFTWARE\Microsoft\SystemCertificates` |
| `HKLM` | `SOFTWARE\Microsoft\Cryptography` |
| `HKCU` | `SOFTWARE\Microsoft\SystemCertificates` |
| `HKCU` | `SOFTWARE\Microsoft\Cryptography` |

These subtrees keep the default scan focused on cryptographic material. Scanning entire hives at unlimited depth would read hundreds of thousands of values through every detector, so it is not the default — set `paths` explicitly (e.g. a hive root with an empty `key`) if you need wider coverage.

---

## Configuration reference

### `registry`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable registry scanning. |
| `paths` | list of [RegistryPath](#registrypath) | crypto subtrees | Registry locations to scan. When empty, defaults to the well-known `HKLM`/`HKCU` `SystemCertificates` and `Cryptography` subtrees (see [Quick start](#quick-start)). |
| `max_depth` | int | `0` | Maximum subkey recursion depth. `0` means unlimited. |
| `max_value_size` | int | `1048576` | Skip values larger than this (bytes). Default is 1 MB. |
| `wow64` | bool | `false` | When `true`, scan both the 64-bit and 32-bit registry views on 64-bit Windows. |
| `include` | [RegistryFilter](#registryfilter) | | Only process keys/values matching these patterns. |
| `exclude` | [RegistryFilter](#registryfilter) | | Skip keys/values matching these patterns. |

### `RegistryPath`

| Field | Type | Description |
|-------|------|-------------|
| `hive` | string | Registry hive. One of `HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`. |
| `key` | string (optional) | Subkey path relative to the hive root (backslash-separated). Omitted or empty scans the entire hive. |

### `RegistryFilter`

| Field | Type | Description |
|-------|------|-------------|
| `keys` | list of string | Regex patterns matched against the key path (forward-slash normalised). |
| `values` | list of string | Regex patterns matched against value names. |

---

## Filtering

Include and exclude filters use Go regular expressions. Key paths are normalised to forward slashes before matching.

- When `include.keys` is non-empty, values are only yielded for keys whose path matches at least one pattern. Subkey traversal continues regardless, so a pattern like `CryptoStore` will match `SOFTWARE/CryptoStore` even when the scan root is `SOFTWARE`.
- When `exclude.keys` is non-empty, keys whose path matches any pattern are pruned entirely (values and all subkeys skipped).
- `include.values` and `exclude.values` work the same way on value names.
- Exclude takes precedence — a key or value matching both include and exclude is skipped.

Example — scan from `SOFTWARE`, yield values only under `CryptoStore` subtrees, skip anything under `Telemetry`:

```yaml
registry:
  enabled: true
  paths:
    - hive: HKLM
      key: 'SOFTWARE'
  include:
    keys:
      - CryptoStore
  exclude:
    keys:
      - Telemetry
```

---

## WOW64 dual-view scanning

On 64-bit Windows, some applications install 32-bit registry keys under `Wow6432Node`. Setting `wow64: true` causes CBOM-Lens to scan both the native 64-bit view and the 32-bit view in a single pass.

```yaml
registry:
  enabled: true
  wow64: true
  paths:
    - hive: HKLM
      key: 'SOFTWARE\Microsoft\Cryptography'
```

Each entry's location URI includes the view (`64` or `32`):

```
registry://HKLM:64/SOFTWARE/Microsoft/Cryptography/MachineGuid
registry://HKLM:32/SOFTWARE/Microsoft/Cryptography/MachineGuid
```

---

## Depth limiting

Set `max_depth` to limit how deep the walker recurses into subkeys. A value of `0` (the default) means unlimited depth.

```yaml
registry:
  enabled: true
  max_depth: 3
  paths:
    - hive: HKCU
      key: 'SOFTWARE'
```

---

## Value types

The scanner reads the following Windows registry value types:

| Registry type | Conversion |
|--------------|------------|
| `REG_BINARY` | Raw bytes |
| `REG_SZ` | UTF-8 string |
| `REG_EXPAND_SZ` | UTF-8 string (unexpanded) |
| `REG_MULTI_SZ` | Strings joined with newlines |

Other types (`REG_DWORD`, `REG_QWORD`, etc.) are silently skipped — they do not contain cryptographic material.

The Windows default value (empty name) appears in location URIs as `(Default)`.

---

## Error handling

The registry walker is designed to be resilient:

- If a value cannot be read (e.g. permission denied), the error is reported but scanning continues with the remaining values and subkeys.
- If `ReadValueNames` fails on a key, the error is reported and the walker still recurses into subkeys.
- If a subkey cannot be opened, the error is reported and the walker continues with the next sibling.

Errors are included in the scan output and do not abort the walk.

---

## Full example

```yaml
version: 0
service:
  mode: manual
registry:
  enabled: true
  max_depth: 5
  max_value_size: 1048576
  wow64: true
  paths:
    - hive: HKLM
      key: 'SOFTWARE\Microsoft\SystemCertificates'
    - hive: HKCU
      key: 'SOFTWARE\Microsoft\SystemCertificates'
  include:
    values:
      - '(?i)cert'
      - '(?i)key'
  exclude:
    keys:
      - Telemetry
      - Diagnostics
```

---

## See also

- [Configuration guide](configuration.md) — narrative overview of all config sections.
- [Configuration reference](config.md) — field-by-field reference.
- [CUE schema](config.cue) — machine-readable schema with defaults and validation.
