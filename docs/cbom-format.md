# CBOM Output Format

CBOM-Lens produces a Cryptographic Bill of Materials (CBOM) that conforms to the [CycloneDX BOM 1.6](https://cyclonedx.org/schema/bom-1.6.schema.json) or [1.7](https://cyclonedx.org/schema/bom-1.7.schema.json) specification.

This document explains how CBOM-Lens models cryptographic assets and how it uses stable `bom-ref` identifiers.

For scanning strategies, see [Scanning use cases & best practices](scanning-use-cases.md). For configuration details, see the [Configuration guide](configuration.md) and [Configuration reference](config.md).

---

## 1. Specification version

Cryptographic assets (certificates, keys, algorithms, and so on) are represented as CycloneDX components with additional properties. The exact JSON structure is defined by the CycloneDX schema, with CBOM-Lens-specific conventions described below.

CBOM-Lens emits **1.6 by default**. Set `cbom.version: "1.7"` in the configuration file to emit 1.7 instead. The schema set for both versions is vendored into the binary, and every emitted document is validated against it before being written or uploaded — a document that fails validation is refused rather than produced. Validation never requires network access.

### What 1.7 adds

The 1.7 schema itself removed nothing, and it deprecates by annotation rather than by constraint, so any 1.6 document also validates as 1.7 unchanged.

CBOM-Lens's own 1.7 output is a different matter, and **1.6 stays the compatibility format**. Where 1.7 supersedes a field, the 1.7 output adopts the replacement and drops the original: the reference fields listed below are cleared in favour of `relatedCryptographicAssets`, and `certificateExtension` is migrated to `certificateFileExtension`. A consumer that reads only 1.6 field names will therefore miss those relationships in a 1.7 document. The single exception is `curve`, which is emitted alongside `ellipticCurve` — see below for why.

For cryptographic assets, 1.7 adds three things worth knowing about:

**A registry of algorithm families and elliptic curves.** `algorithmProperties` gains `algorithmFamily` and `ellipticCurve`, whose permitted values come from a registry published alongside the specification. Both are *closed* enumerations — a value outside the registry makes the whole document fail validation, so CBOM-Lens emits them only where a scanned artifact maps to a registry entry, and omits them otherwise. A missing field means "not established"; it never means the algorithm is unrecognised. Curves are namespaced, for example `secg/secp256r1` rather than a bare `secp256r1`.

`ellipticCurve` is emitted *alongside* the older `curve` field, not instead of it. `curve` remains valid in 1.7 and is only removed in CycloneDX 2.0, many consumers still read it, and several conversion tools silently discard the newer field — so emitting both is what keeps information from being lost in transit.

**Typed relationships between crypto assets.** The individual reference fields (`signatureAlgorithmRef`, `subjectPublicKeyRef`, `algorithmRef`, `cryptoRefArray`) are superseded by a single `relatedCryptographicAssets` array of typed edges. CBOM-Lens builds these from its internal relationship model rather than by copying the old fields, which means a 1.7 document cannot contain a reference that points at nothing. The 1.6 output keeps the original fields for compatibility.

**Richer certificate metadata.** `certificateProperties` gains a serial number, fingerprint, file extension, certificate state, parsed extensions, and lifecycle dates (creation, activation, deactivation, revocation).

Of those, CBOM-Lens currently populates **only `certificateFileExtension`**, migrated from 1.6's `certificateExtension`. The serial number, certificate state, parsed extensions and lifecycle dates are not emitted. The certificate fingerprints *are* emitted, but as component-level `hashes` rather than in `certificateProperties.fingerprint`. Populating the rest is future work.

Two smaller additions: the `key-wrap` primitive, and `tlsGroups` / `tlsSignatureSchemes` on cipher suites.

---

## 2. Unique yet Secure `bom-ref` Identifiers

CBOM-Lens tracks discovered cryptographic components using content-based identifiers (sha256) during the scanning and correlation phase. This approach enables accurate correlation of identical keys or certificates discovered across different contexts—filesystem scans, container images, and network port scans.

Those hashes are not what the document publishes. A digest printed in a shared artifact is an invitation to match it offline against candidate inputs, and it says more about the scanned material than a reference needs to say in order to do its job, which is to join components inside one document.

To address this security concern, CBOM-Lens post-processes the CBOM after correlation is complete. It replaces each content-based hash with a UUIDv5 derived from the reference it replaces (`uuid.NewSHA1` over the full pre-rewrite `bom-ref`), so the digest never reaches the document.

**Key characteristics:**
- **Unique**: Each component receives a distinct identifier within the CBOM
- **Opaque, not one-way**: the UUID hides the digest but does not break the derivation — it is a deterministic function of the reference, so anyone able to reconstruct that reference can reconstruct the UUID
- **Stable**: the same component data yields the same reference, and therefore the same UUID, in every document that describes it
- **Format-preserving**: Original reference format (e.g., `component@hash`) is maintained as `component@uuid`

Nearly every reference is derived from material that is public anyway — a certificate, a public key, or an algorithm's own description in the document. The one exception is a post-quantum private key, whose reference is derived from secret material; the consequences of the determinism above are set out in [Private-key references](pqc-support.md#private-key-references).

> [!WARNING]
> A `bom-ref` is derived from the component's contents, so **correcting a component's data moves its
> reference**. A release that fixes a wrong primitive, cipher function or key size will change the
> refs of the affected components even though the document format is unchanged. If you join records
> on `bom-ref` across releases, treat a ref change as "the same asset, described more accurately"
> rather than as a new asset, and consult the release notes for the specific refs that moved.

---

## 3. Example algorithm component

Example of an algorithm component in a CBOM:

```json
{
  "bom-ref": "crypto/algorithm/rsa-4096@3f48a0ca-c944-4ac4-b37b-df51be5ede90",
  "type": "cryptographic-asset",
  "name": "RSA-4096",
  "evidence": {
    "occurrences": [
      { "location": "filesystem:///testing/cert.pem" },
      { "location": "filesystem:///testing/key.pem" }
    ]
  }
}
```

- `evidence.occurrences` lists where the algorithm was observed.
- `bom-ref` uniquely identifies the algorithm + its BOM properties.

---

## 4. Post-Quantum Cryptography (PQC)

Go's standard library does not (yet) implement PQC algorithms, but CBOM-Lens can still **detect** and model them where present.

Recognised families are **ML-DSA** (FIPS 204), **SLH-DSA** (FIPS 205, all 12 parameter sets), **ML-KEM** (FIPS 203), **XMSS**, **XMSS-MT** and **HSS-LMS**. See [PQC support](pqc-support.md) for the per-algorithm detail and for what is deliberately not claimed.

Example (truncated) CBOM entry:

```json
{
  "bom-ref": "crypto/algorithm/ml-dsa-65@03acfb52-5eec-466f-88dc-3b9837ffc17e",
  "type": "cryptographic-asset",
  "name": "ML-DSA-65",
  "properties": [
    { "name": "ilm:component:algorithm:pqc:private_key_size", "value": "4032" },
    { "name": "ilm:component:algorithm:pqc:public_key_size", "value": "1952" },
    { "name": "ilm:component:algorithm:pqc:signature_size", "value": "3309" }
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

The property set depends on what the algorithm is. A signature scheme carries `private_key_size`, `public_key_size` and `signature_size`, as above. A KEM has no signature, so ML-KEM carries `ilm:component:algorithm:pqc:ciphertext_size` in place of `signature_size`, with the encapsulation and decapsulation key sizes reported as the public and private key sizes. See [PQC support](pqc-support.md) for the per-algorithm detail.

---

## 5. Evidence and correlation

CBOM-Lens attaches **evidence** to components to describe where an asset was observed, for example:

- Filesystem paths.
- Container image layers or paths.
- Network endpoints (protocol://host:port).

By combining evidence with stable `bom-ref` identifiers, analysis tools can:

- See all the places where a particular certificate or key is used.
- Understand relationships between algorithms, keys, and certificates.

### Location format

cbom-lens reports source locations as URIs

- Filesystem: `filesystem:///absolute/path`
- Container: `container://<config-name>/<image-ref>/<absolute-path>`
  - <config-name> comes from your configuration
  - <image-ref> can be a tag (e.g., repo:tag) or a digest (e.g., sha256:...)
- Network endpoint: `tcp://host:port`

Example:

`cbom-lens` correlates the same TLS certificate across three sources: the filesystem (`cert.pem`), the container image (`cert.pem`), and the HTTPS server listening on port `:37257`.

```json
"evidence": {
  "occurrences": [
    { "location": "container://docker/image-tag-or-digest//cert.pem" },
    { "location": "filesystem:///tmp/cert.pem" },
    { "location": "tcp://localhost:37257" }
  ]
}
```

---

## 6. Metric Definitions

### 6.1. Sources

- **cbom_lens_sources_total**: Tracks each top-level source that the scanner attempts to process. This includes:
  - Filesystem root directories
  - Docker engines
  - Nmap scan targets

- **cbom_lens_sources_errors**: Counts sources that failed at initialization or access level, preventing any scanning of their contents. This includes:
  - Filesystem does not exists or not accessbile
  - Container engine can't be accessed
  - Nmap binary is missing or can't be executed
  - Other unspecified errors

### 6.2. Files

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

### 6.3. Example in CBOM

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

## 7. Next steps

- For scanning use cases and strategies: see [Scanning use cases & best practices](scanning-use-cases.md).
- For configuration details: see the [Configuration guide](configuration.md) and [Configuration reference](config.md).
- For extending CBOM-Lens to recognize new algorithms or formats: see [Extending detectors](extending-detectors.md).
