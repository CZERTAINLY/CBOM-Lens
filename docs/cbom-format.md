# CBOM Output Format

CBOM-Lens produces a Cryptographic Bill of Materials (CBOM) that conforms to the [CycloneDX BOM 1.6](https://cyclonedx.org/schema/bom-1.6.schema.json) specification.

This document explains how CBOM-Lens models cryptographic assets and how it uses stable `bom-ref` identifiers.

For scanning strategies, see [Scanning use cases & best practices](scanning-use-cases.md). For configuration details, see the [Configuration guide](configuration.md) and [Configuration reference](config.md).

---

## 1. CycloneDX 1.6

- CBOM-Lens uses CycloneDX 1.6 as the base schema for its output.
- Cryptographic assets (certificates, keys, algorithms, etc.) are represented as CycloneDX components with additional properties.

The exact JSON structure is defined by the CycloneDX schema, with CBOM-Lens-specific conventions described below.

---

## 2. Stable `bom-ref` identifiers

Each cryptographic asset discovered by CBOM-Lens is assigned a stable `bom-ref` (BOM reference) derived from its content.

- The default hash algorithm is **SHA-256**.
- `bom-ref` values are designed to be stable across scans and sources, so the same asset gets the same `bom-ref` wherever it appears.

This enables:

- Correlating the same key or certificate across filesystem, container, and port scans.
- De-duplicating assets in analysis tools.

---

## 3. Exceptions: private keys and algorithms

There are two important exceptions to the "hash the content" rule.

### 3.1 Private keys

Hashing a private key directly would leak sensitive information (the hash uniquely identifies the key material).

To avoid this, CBOM-Lens uses the hash of the **corresponding public key** instead.

Example:

```json
[
  {"bom-ref": "crypto/key/rsa-4096@sha256:f1ac7a3953323b932aade7e47c045d7981e4602fe465883d21f77051cf3c2dbc"},
  {"bom-ref": "crypto/private_key/rsa-4096@sha256:f1ac7a3953323b932aade7e47c045d7981e4602fe465883d21f77051cf3c2dbc"}
]
```

In this example, the public and private key share the same hash suffix because it is based on the public key.

### 3.2 Algorithms

Algorithms themselves (e.g., `RSA-4096`, `SHA-256`, PQC algorithms) do not have inherent content to hash.

For algorithm components, CBOM-Lens:

- Computes a hash of the component's **CycloneDX JSON representation**.
- Excludes the `bom-ref` and `evidence` fields from this hash to avoid circular dependencies and unstable references.

This ensures:

- Different algorithms always receive unique references.
- The same algorithm with different BOM properties yields distinct `bom-ref` values.

---

## 4. Example algorithm component

Example of an algorithm component in a CBOM:

```json
{
  "bom-ref": "crypto/algorithm/rsa-4096@sha256:2cc0b015108f202753b120182f3c437db4d5bf6e668b019a1f9099f5709e167f",
  "type": "cryptographic-asset",
  "name": "RSA-4096",
  "evidence": {
    "occurrences": [
      { "location": "testing/cert.pem" },
      { "location": "testing/key.pem" }
    ]
  }
}
```

- `evidence.occurrences` lists where the algorithm was observed.
- `bom-ref` uniquely identifies the algorithm + its BOM properties.

---

## 5. Post-Quantum Cryptography (PQC)

Go's standard library does not (yet) implement PQC algorithms, but CBOM-Lens can still **detect** and model them where present.

Support currently includes members of the **ML-DS** family (e.g., `ML-DSA-65`).

Example (truncated) CBOM entry:

```json
{
  "bom-ref": "crypto/algorithm/ml-dsa-65@sha256:f8c9a2448272eebee3bf9c777bff35d1f84d59166534cc848eed418f3fbc08a3",
  "type": "cryptographic-asset",
  "name": "ML-DSA-65",
  "properties": [
    { "name": "czertainly:component:algorithm:pqc:private_key_size", "value": "4032" },
    { "name": "czertainly:component:algorithm:pqc:public_key_size", "value": "1952" },
    { "name": "czertainly:component:algorithm:pqc:signature_size", "value": "3309" }
  ],
  "evidence": {
    "occurrences": [
      { "location": "testing/pqc.pem" }
    ]
  },
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": {
      "primitive": "ae",
      "parameterSetIdentifier": "65",
      "executionEnvironment": "software-plain-ram",
      "certificationLevel": [ "none" ],
      "cryptoFunctions": [ "sign" ],
      "classicalSecurityLevel": 192,
      "nistQuantumSecurityLevel": 3
    },
    "oid": "2.16.840.1.101.3.4.3.18"
  }
}
```

This representation captures algorithm characteristics and their occurrences while still using stable `bom-ref` identifiers.

---

## 6. Evidence and correlation

CBOM-Lens attaches **evidence** to components to describe where an asset was observed, for example:

- Filesystem paths.
- Container image layers or paths.
- Network endpoints (host:port, protocol).

By combining evidence with stable `bom-ref` identifiers, analysis tools can:

- See all the places where a particular certificate or key is used.
- Understand relationships between algorithms, keys, and certificates.

---

## 7. Metric Definitions

### 7.1. Sources

- **cbom_lens_sources_total**: Tracks each top-level source that the scanner attempts to process. This includes:
  - Filesystem root directories
  - Docker engines
  - Nmap scan targets

- **cbom_lens_sources_errors**: Counts sources that failed at initialization or access level, preventing any scanning of their contents. This includes:
  - Filesystem does not exists or not accessbile
  - Container engine can't be accessed
  - Nmap binary is missing or can't be executed
  - Other unspecified errors

### 7.2. Files

- **cbom_lens_files_total**: Counts every file path encountered during the scan, regardless of whether it was successfully processed, excluded, or errored.

- **cbom_lens_files_excluded**: Tracks files that were successfully accessed but intentionally skipped based on:
  - File size limits
  - Ignore patterns or rules
  - Other exclusion criteria

- **cbom_lens_files_errors**: Counts files that could not be read or accessed due to:
  - Permission errors
  - File open failures
  - Read errors
  - Other I/O problems

### 7.3. Example in CBOM

```json
"properties": [
  {
    "name": "cbom_lens_files_errors",
    "value": "0"
  },
  {
    "name": "cbom_lens_files_excluded",
    "value": "0"
  },
  {
    "name": "cbom_lens_files_total",
    "value": "3"
  },
  {
    "name": "cbom_lens_sources_errors",
    "value": "0"
  },
  {
    "name": "cbom_lens_sources_total",
    "value": "1"
  }
]
```

---

## 8. Next steps

- For scanning use cases and strategies: see [Scanning use cases & best practices](scanning-use-cases.md).
- For configuration details: see the [Configuration guide](configuration.md) and [Configuration reference](config.md).
- For extending CBOM-Lens to recognize new algorithms or formats: see [Extending detectors](extending-detectors.md).
