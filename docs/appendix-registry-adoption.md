# Appendix: who emits the CycloneDX 1.7 cryptography registry

CBOM-Lens claims to be the first known CBOM producer to emit `algorithmFamily`
and `ellipticCurve`. This appendix records the evidence for that claim, when it
was gathered, and how to re-check it, so the claim can be falsified rather than
taken on trust.

**Surveyed 2026-07-30**, against the default branch of each repository. Nothing
here is a permanent statement: the point of writing down the method is that the
result will change.

## Method

Clone each candidate and look for the two field names, then — this is the part
that matters — separate three different kinds of hit:

1. **Vendored schemas and upstream spec fixtures.** Every library that supports
   1.7 carries `bom-1.7.schema.json` and the spec's own
   `valid-cryptography-*-1.7.json` test files. These mention both fields and
   prove nothing about the tool.
2. **Reading the field.** An audit rule or validator that matches on
   `algorithmFamily` consumes it; it does not produce it.
3. **Populating the field.** Code that assigns it while building a component.
   Only this makes a tool a producer of the registry fields.

```sh
git clone --depth 1 https://github.com/<owner>/<repo>
grep -rn 'algorithmFamily\|ellipticCurve' <repo> | grep -v '/\.git/'
# then classify each hit as schema / read / populate
```

## Producers

None of these populate either field.

| Tool | Produces CBOMs? | Emits the registry fields? | Evidence |
|---|---|---|---|
| `CycloneDX/cdxgen` | yes | **no** | Builds crypto assets in `lib/helpers/golem.js`, `lib/helpers/rusi.js`, `lib/managers/binary.js`; all three emit `algorithmProperties: { primitive }` only and contain **zero** occurrences of either field. The names appear only in `data/*.schema.json`, in `data/rules/cbom-security.yaml` (a rule that *reads* `algorithmFamily` to flag weak algorithms), and in `lib/stages/postgen/auditBom.poku.js` (a test fixture). Its default spec version is indeed 1.7 (`bin/cdxgen.js:362`), and it has genuine 1.7 support elsewhere — `postgen.js` correctly downgrades `certificateFileExtension` → `certificateExtension` for pre-1.7 targets. |
| `PQCA/sonar-cryptography` | yes | **no** | Zero `algorithmFamily`. The 23 files matching `ellipticCurve` are its own domain model (`com.ibm.mapper.model.EllipticCurve`) and Java local variables in detection tests — not the CycloneDX field. |
| `PQCA/cbomkit` | yes | **no** | Zero occurrences of either. |
| `IBM/cbomkit-theia` | yes | **no** | Zero occurrences of either. |
| `Santandersecurityresearch/cryptobom-forge` | yes | **no** | Zero occurrences of either. |
| `anthonyharrison/cbom4cert` | yes | **no** | Zero occurrences of either. |
| `CycloneDX/cyclonedx-cli` | converter | **no** | Zero occurrences of either. |

## Libraries

A library modelling the fields is a precondition for emitting them, not the same
thing. Only `cyclonedx-core-java` and `cyclonedx-go` model them at all.

| Library | Models the fields? | Detail |
|---|---|---|
| `cyclonedx-core-java` | **yes**, since **13.0.0** | `AlgorithmProperties.java` gained the accessors in tag `cyclonedx-core-java-13.0.0` (released 2026-07-16); `12.2.0` has zero occurrences. |
| `cyclonedx-go` | **yes** | `cyclonedx.go` declares both as plain `string`. `convert.go` clears them when the target is below 1.7 — correct downgrade behaviour, since the fields do not exist before 1.7. |
| `cyclonedx-dotnet-library` | no | `src/CycloneDX.Core/Models/Crypto/CryptoProperties.cs` has zero occurrences; the hits are schemas and spec fixtures only. |
| `cyclonedx-python-lib` | no | `cyclonedx/model/crypto.py` has zero occurrences; its 1.7 schema is still `bom-1.7.SNAPSHOT`. |
| `cyclonedx-javascript-library` | no | Nothing in `src/`; its 1.7 schema is also `bom-1.7.SNAPSHOT`. |

A round-trip through the three libraries that do not model the fields therefore
loses them. That is a gap in 1.7 coverage, not a bug: they simply have not
implemented the fields yet.

## What this does and does not establish

It establishes that across seven public CBOM producers and six CycloneDX
libraries, no producer populated either field as of 2026-07-30.

It cannot establish a global negative. The survey covers public repositories we
could identify; a closed-source or unlisted tool may already do this. Hence the
wording "first **known** producer" rather than a flat "first".

**If you find a producer that got there first, open an issue and we will correct
the claim.**

---

# Appendix: CBOM tool comparison

Surveyed **2026-07-31** against the default branch of each repository, by cloning
and reading the source. Every row was gathered with a positive control (a term
that must match in that repo) so that a zero is evidence of absence rather than
a broken search — a distinction that matters, because a zero-hit grep against a
path that does not exist looks identical to a genuine zero.

## Producers

"Emits" means code assigns the field while building a component. Mentions in a
vendored schema, in a rule that *reads* the field, or in a test fixture do not
count.

| Tool | Emits crypto assets | Highest CycloneDX version | `algorithmFamily` / `ellipticCurve` | `relatedCryptographicAssets` | PQC awareness |
|---|---|---|---|---|---|
| **CBOM-Lens** | yes | **1.7**, selectable via `cbom.version` | **yes** | yes | 21 registry OIDs |
| `CycloneDX/cdxgen` | yes — `lib/helpers/golem.js`, `lib/helpers/rusi.js`, `lib/managers/binary.js` | **1.7**, and it is the default (`bin/cdxgen.js:362`) | no — emits `algorithmProperties: { primitive }` only; the names appear only in vendored schemas, in `data/rules/cbom-security.yaml` which *reads* `algorithmFamily` to flag weak algorithms, and in a `.poku.js` test fixture | no | 9 files mention PQC names |
| `PQCA/sonar-cryptography` | yes | no 1.7 reference in the repo | no — its 23 `ellipticCurve` matches are its own `com.ibm.mapper.model.EllipticCurve` domain class and Java locals in tests | no | 39 files — the strongest PQC detector surveyed |
| `PQCA/cbomkit` | yes | no 1.7 reference | no | no | 3 files |
| `IBM/cbomkit-theia` | yes | no 1.7 reference | no | no | none |
| `Santandersecurityresearch/cryptobom-forge` | yes | emits `specVersion: "1.4-cbom-1.0"` — the pre-standard IBM CBOM extension to CycloneDX 1.4, predating standardised crypto assets in 1.6 | no | no | none |
| `anthonyharrison/cbom4cert` | yes, but delegates serialisation to `lib4sbom` | not established here (depends on `lib4sbom`) | no | no | none |
| `CycloneDX/cyclonedx-cli` | no — converter only, constructs no crypto assets | 1.7 aware | n/a | no | n/a |

## Libraries

A library modelling a field is a precondition for a producer emitting it, so
this table explains much of the one above. Judged on source directories only,
excluding vendored schemas, resources and tests.

| Library | `algorithmFamily` / `ellipticCurve` | `relatedCryptographicAssets` |
|---|---|---|
| `cyclonedx-go` (used by CBOM-Lens) | yes | yes |
| `cyclonedx-core-java` ≥ **13.0.0** | yes | yes |
| `cyclonedx-dotnet-library` | **no** — `Models/Algorithms/AlgorithmProperties.cs` carries `Curve` but neither registry field | yes — full `RelatedCryptographicAsset` model |
| `cyclonedx-python-lib` | no | no |
| `cyclonedx-javascript-library` | no | no |

Two observations worth recording:

- **1.7 crypto support is arriving piecemeal, not as a unit.** The .NET library
  models the new relationship array but not the registry fields, so "supports
  1.7" is not a single question. Python and JavaScript ship their 1.7 schema as
  `bom-1.7.SNAPSHOT` and model neither.
- **`.NET` types `ClassicalSecurityLevel` and `NistQuantumSecurityLevel` as
  non-nullable `int`**, so an unknown algorithm serialises as `0` — the same
  "asserting zero bits of security about an algorithm we merely do not
  recognise" ambiguity CBOM-Lens removed by making those fields pointers.

## The relationship vocabulary is settled by the specification

`relatedCryptographicAssets[].type` has no enum in the schema — only
`examples: [publicKey, privateKey, algorithm]` and the description "Specifies the
mechanism by which the cryptographic asset is secured by". Since no other
producer emits the field, the specification's own conformance fixtures are the
only authority. At `CycloneDX/specification@fac1ff6`:

```jsonc
// tools/src/test/resources/1.7/valid-cryptography-certificate-1.7.json
[{ "type": "algorithm",  "ref": "6b00f384-…" },
 { "type": "publicKey",  "ref": "ceb37320-…" }]

// tools/src/test/resources/1.7/valid-cryptography-full-1.7.json
[{ "type": "publicKey",  "ref": "public-key-ref" },
 { "type": "privateKey", "ref": "private-key-ref" },
 { "type": "algorithm",  "ref": "signing-algorithm-ref" }]
```

So `type` names **the kind of the referenced asset**, not the role of the edge.
A certificate's signature algorithm and its subject key are distinguished
because they are different kinds — `algorithm` and `publicKey` — and no
role-named vocabulary such as `signatureAlgorithm` is used or needed. Inventing
one would also be a poor bet in a release where CycloneDX closed
`algorithmFamily` and `ellipticCurve` into enumerations.

## Reproducing this

```sh
git clone --depth 1 https://github.com/<owner>/<repo>
# positive control first: prove the search works in this tree
grep -ril cyclonedx <repo> | grep -v '/\.git/' | wc -l
grep -rn 'algorithmFamily\|ellipticCurve\|relatedCryptographicAsset' <repo> | grep -v '/\.git/'
# then classify every hit as vendored-schema / reads-the-field / populates-the-field
```
