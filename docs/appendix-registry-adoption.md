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
