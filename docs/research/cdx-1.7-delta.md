# CycloneDX 1.7 delta — research for cbom-lens (issue #175)

Date: 2026-07-28. Sources: local diff of Go module cache `cyclonedx-go@v0.10.0`
vs `@v0.11.0` (code-verified), canonical schemas from
github.com/CycloneDX/specification (tag `1.7` + master, fetched 2026-07-28).
Everything below is code/schema-verified unless marked *(inferred)*.

## 1. Upgrade: cyclonedx-go v0.10.0 (current) → v0.11.0

- go.mod pins **v0.10.0**; **v0.11.0** (released 2026-05-14) is the first and
  only release with 1.7 support — added in one PR,
  [#257](https://github.com/CycloneDX/cyclonedx-go/pull/257), closing
  [#247](https://github.com/CycloneDX/cyclonedx-go/issues/247). Same `go 1.23`
  directive, zero dependency changes.
  [Releases](https://github.com/CycloneDX/cyclonedx-go/releases)
- New API: `cdx.SpecVersion1_7` (iota 8, `String() == "1.7"`), JSON-schema URL
  map entry `http://cyclonedx.org/schema/bom-1.7.schema.json` (http, not
  https), XML ns `.../bom/1.7`; `specVersion` JSON unmarshal now accepts "1.7".

### Compile-breaking changes (v0.10.0 → v0.11.0)

1. **`Evidence.Identity`**: `*[]EvidenceIdentity` → `*EvidenceIdentityChoice`
   (wrapper with `Identity *EvidenceIdentity` (deprecated) /
   `Identities *[]EvidenceIdentity`; custom JSON marshal, errors if both set).
   cbom-lens only uses `Evidence.Occurrences` → **not hit** in prod code.
2. **`IKEv2TransformTypes`** fields: `*[]BOMReference` → typed structs
   `*[]IKEv2Enc/Prf/Integ/Ke/Auth` (each keeps deprecated 1.6 string form in a
   `BOMRef BOMReference json:"-"` field + 1.7 structured Name/Algorithm form).
   Not used by cbom-lens prod code, but **pinned in
   `internal/bom/refintegrity_test.go`'s inventory list** (lines ~424–428
   expect `*[]cyclonedx.BOMReference`) → that tripwire test fails on upgrade
   and must be re-pinned (it already anticipates `IKEv2Auth.BOMRef`, line ~587).

### Behavior changes

- **`NewBOM()` now defaults to SpecVersion1_7** (+1.7 schema URL/XMLNS).
  cbom-lens builds `cdx.BOM{}` literals in `emit16.go` → unaffected.
- **`License` Marshal(JSON|XML) now errors** when both `ID` and `Name` set, or
  neither. cbom-lens emits no licenses → unaffected.
- **`EncodeVersion` downgrade logic extended** — new `convertCryptoProperties`
  strips 1.7-only crypto fields when encoding at <1.7 (v0.10.0 had *no* crypto
  downgrade at all). Plain `Encode()` (used by `bom.Validator`) still writes
  the struct as-is, no conversion.
- Service XML: `Data` element renamed `data>classification` → `data>dataflow`
  (JSON unchanged; cbom-lens is JSON-only).
- `MediaType/SpecVersion.String()` bounds fix (cosmetic).
- PR #256 (also in v0.11.0) backfills 5 missing 1.6 fields on
  `DataClassification` (Name, Description, Governance, Source, Destination)
  + `LicenseChoice` gains BOMRef/Acknowledgement/Licensing/ExpressionDetails.

### New 1.7 struct surface (crypto-relevant)

- `CryptoAlgorithmProperties`: + `AlgorithmFamily string`,
  `EllipticCurve string`; `Curve` deprecated (kept, still marshals).
- `CertificateProperties`: + `SerialNumber`, `CertificateFileExtension`
  (replaces deprecated `CertificateExtension`), `Fingerprint *Hash`,
  `CertificateState *[]CertificateState` (oneOf Predefined enum
  pre-activation/active/suspended/deactivated/revoked/destroyed | Custom),
  `CertificateExtensions *[]CertificateExtension` (oneOf Common enum —
  basicConstraints, keyUsage, extendedKeyUsage, subjectAlternativeName,
  authorityKeyIdentifier, subjectKeyIdentifier, authorityInformationAccess,
  certificatePolicies, crlDistributionPoints, signedCertificateTimestamp — |
  Custom), `RelatedCryptographicAssets *[]RelatedCryptographicAsset`, and 5
  lifecycle dates (Creation/Activation/Deactivation/Revocation/Destruction);
  `SignatureAlgorithmRef`/`SubjectPublicKeyRef` deprecated → use
  RelatedCryptographicAssets.
- `RelatedCryptoMaterialProperties`: + `Fingerprint *Hash`,
  `RelatedCryptographicAssets`; `AlgorithmRef` deprecated.
- `CryptoProtocolProperties`: + `RelatedCryptographicAssets`; `CryptoRefArray`
  deprecated. `CipherSuite`: + `TLSGroups`, `TLSSignatureSchemes *[]string`.
- `RelatedCryptographicAsset{Type string, Ref string}` — Type is free-form
  ("publicKey", "privateKey", "algorithm", … examples only, not an enum).
- New enum values: `CryptoPrimitiveKeyWrap` ("key-wrap"); protocol types dtls,
  quic, eap-aka, eap-aka-prime, prins, 5g-aka; `HashAlgoStreebog256/512`.
- Non-crypto 1.7: top-level `BOM.Citations`, `Metadata.DistributionConstraints`
  (TLP), `Definitions.Patents`, Component `IsExternal`/`PatentAssertions`/
  `VersionRange`, `ExternalReference.Properties`, ERTypes patent/
  patent-family/patent-assertion/citation, `EvidenceIdentity.ConcludedValue`.
  These add "def/use" ref fields the refintegrity walker will pick up
  (Citation.AttributedTo, PatentFamily.Members, PatentAssertion.PatentRefs,
  AsserterChoice.BOMRef, RelatedCryptographicAsset.Ref …) → inventory update.

## 2. Spec 1.7 vs 1.6, crypto/CBOM focus (schema-diffed, not just prose)

- `specVersion: "1.7"`; `$schema`: `http://cyclonedx.org/schema/bom-1.7.schema.json`
  ($id; `$schema` property itself remains an unconstrained string, as in 1.6).
  Spec released 2025-10-21; ECMA-424 2nd ed. expected Dec 2025.
  [Announcement](https://cyclonedx.org/news/cyclonedx-v1.7-released/)
- **algorithmProperties**: only additions are `algorithmFamily` and
  `ellipticCurve` — both `$ref` into the NEW external
  `cryptography-defs.schema.json` (`algorithmFamiliesEnum`: 77 values at tag
  1.7, 93 on master incl. SM2/3/4/9, Argon2, HPKE, DRBGs; KMAC removed on
  master — the registry is a moving target; `ellipticCurvesEnum`: 246 curves,
  namespaced like `nist/P-256`, `brainpool/…`, `bls/…`). **No** new
  primitives besides `key-wrap`, **no** new executionEnvironments,
  implementationPlatforms, certificationLevels or cryptoFunctions;
  `nistQuantumSecurityLevel` unchanged (integer 0–6).
- **"Crypto-asset semantics"** = the deprecation of ad-hoc `*Ref` fields in
  favor of the uniform `relatedCryptographicAssets` array (typed edges) on
  certificateProperties, protocolProperties and
  relatedCryptoMaterialProperties, plus the external crypto registry
  (families/curves published as standalone schema for non-CycloneDX reuse).
- Nothing was removed; all 1.6 crypto fields still validate in 1.7 —
  deprecations are annotations (`"deprecated": true`), not constraints.
- Top-level additions relevant to a producer: `citations` (multi-tool
  enrichment provenance — could later attribute cbom-lens detectors),
  `metadata.distributionConstraints.tlp`, patents (not crypto-relevant).

## 3. 1.7 JSON schema for offline validation

- Canonical: `https://github.com/CycloneDX/specification/blob/1.7/schema/bom-1.7.schema.json`
  (also served at cyclonedx.org/schema/). Draft-07, same as 1.6.
- External `$ref`s of bom-1.7.schema.json (exact set, grepped):
  `spdx.schema.json`, `jsf-0.82.schema.json#/definitions/signature`, and
  **NEW** `cryptography-defs.schema.json#/definitions/{algorithmFamiliesEnum,ellipticCurvesEnum}`
  ($id `http://cyclonedx.org/schema/cryptography-defs.schema.json`).
- So the validator's 1.7 `schemaSet` needs **4 embeds**: bom-1.7 + spdx + jsf
  (jsf-0.82 unchanged — repo's copy is byte-identical to canonical) +
  cryptography-defs. Exactly what the `internal/bom/validator.go` comment
  anticipated. Register cryptography-defs under its absolute URI like the
  other subs; it has no external refs of its own → order-independent.
- spdx.schema.json: repo already embeds `v1.1-3.28.0` (newer than the
  `v1.0-3.17` copy cyclonedx-go v0.11.0 ships) — canonical master is also
  v1.1-3.28.0, so the existing embed can be shared by the 1.6 and 1.7 sets
  *(inferred: spdx schema is version-independent across 1.6/1.7; the spec repo
  keeps a single copy)*.
- Pin the **tag-1.7** schema rather than master: master already drifted
  (16 algorithm families added, KMAC removed, description typo fixes).
  cyclonedx-go v0.11.0's bundled bom-1.7 copy is a master snapshot, not the
  tag (differs only in description text — harmless but not canonical).

## 4. Ecosystem stance / gaps

- cyclonedx-go v0.11.0 covers the full 1.7 struct surface including crypto,
  BUT `AlgorithmFamily`/`EllipticCurve` are plain `string` — the registry
  enums are **not** typed as Go constants; producers must emit registry
  values verbatim or fail schema validation. *(gap, by design)*
- cyclonedx-go does **not ship** `cryptography-defs.schema.json` in its
  `schema/` dir even though its bundled bom-1.7 refs it — irrelevant at
  runtime (the lib only validates in its own tests) but confirms cbom-lens
  must source the file from the specification repo, not the module.
- No open cyclonedx-go issues about 1.7 gaps/regressions as of 2026-07-28
  ([issue list](https://github.com/CycloneDX/cyclonedx-go/issues); still-open
  schema-consistency bugs #196/#223 predate 1.7).
- cyclonedx-cli supports 1.7 (validate/convert) since v0.30.0, current
  v0.33.x *(dates via web summaries — low confidence on exact versions)*;
  broader ecosystem still catching up (e.g. trivy discussion
  [#10184](https://github.com/aquasecurity/trivy/discussions/10184)).
- Consumer note: `serialNumber`+`fingerprint` on certificateProperties remove
  the need for cbom-lens's wrong-PEM/serial guards downstream; certificate
  lifecycle states map 1:1 to CZERTAINLY status vocabulary *(inferred)*.
