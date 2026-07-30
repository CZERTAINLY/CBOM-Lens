# Vendored CycloneDX JSON schemas

These schemas are embedded into the binary (see `internal/bom/validator.go`)
so that BOM validation is fully offline and fail-closed: the schema compiler
has all HTTP/HTTPS loaders removed, and every `$ref` must resolve against the
files vendored here.

All files originate from the [CycloneDX specification](https://github.com/CycloneDX/specification)
repository and are licensed under Apache-2.0.

## Provenance

| File | Upstream source | sha256 |
| ---- | --------------- | ------ |
| `bom-1.6.schema.json` | `schema/bom-1.6.schema.json`, snapshot of the `master` branch (pre-existing vendored copy; predates the pinned commit below) | `0a12d5c3396cba7bf6758045257bc8bb7c421eef96d773c773b4e4b67b5f7828` |
| `spdx.schema.json` | `schema/spdx.schema.json` @ [`c9f1780c06d2c6a295d97981f42e3e419a9ea4b4`](https://raw.githubusercontent.com/CycloneDX/specification/c9f1780c06d2c6a295d97981f42e3e419a9ea4b4/schema/spdx.schema.json) | `ea6e844ee6fba1e93473d94834d0ee0996970533497935f932f73d488ffdf4a3` |
| `jsf-0.82.schema.json` | `schema/jsf-0.82.schema.json` @ [`c9f1780c06d2c6a295d97981f42e3e419a9ea4b4`](https://raw.githubusercontent.com/CycloneDX/specification/c9f1780c06d2c6a295d97981f42e3e419a9ea4b4/schema/jsf-0.82.schema.json) | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |
| `bom-1.7.schema.json` | `schema/bom-1.7.schema.json` @ [`b29bae660048e0ad2fbc5f2972927b442ce951c4`](https://raw.githubusercontent.com/CycloneDX/specification/b29bae660048e0ad2fbc5f2972927b442ce951c4/schema/bom-1.7.schema.json) (tag `1.7.1`) | `73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce` |
| `cryptography-defs.schema.json` | `schema/cryptography-defs.schema.json` @ [`b29bae660048e0ad2fbc5f2972927b442ce951c4`](https://raw.githubusercontent.com/CycloneDX/specification/b29bae660048e0ad2fbc5f2972927b442ce951c4/schema/cryptography-defs.schema.json) (tag `1.7.1`) | `027b059a729a06d591bac79a584ef04f83fc32d91a826fdba6ad3c98a10e5b44` |

## Notes

- `bom-1.6.schema.json` declares `$id: http://cyclonedx.org/schema/bom-1.6.schema.json`
  and references `spdx.schema.json` and `jsf-0.82.schema.json` via relative
  `$ref`s, which resolve to `http://cyclonedx.org/schema/spdx.schema.json` and
  `http://cyclonedx.org/schema/jsf-0.82.schema.json`. The vendored subschemas
  carry exactly those `$id`s.
- `bom-1.7.schema.json` declares `$id: http://cyclonedx.org/schema/bom-1.7.schema.json`
  and adds a third relative `$ref` target, `cryptography-defs.schema.json`,
  which resolves to `http://cyclonedx.org/schema/cryptography-defs.schema.json`
  (note `http`, not `https` — relative `$ref`s resolve against the referring
  schema's `$id`, so co-locating the files on disk is not enough). The vendored
  copy carries exactly that `$id` and has no external `$ref`s of its own.
  `spdx.schema.json` and `jsf-0.82.schema.json` at tag `1.7.1` are
  byte-identical to the copies vendored above (verified with `cmp`), so the
  1.6 and 1.7 schema sets share them.
- `cryptography-defs.schema.json` is a *living registry*: upstream edits
  `ellipticCurvesEnum` (246 values at this pin) and `algorithmFamiliesEnum`
  (93 values at this pin) between releases, at an unversioned URL. The 1.7
  mapping tables in `internal/bom/cdx17map.go` are therefore validated against
  this vendored snapshot by `TestCurveTables17_ValuesAreInEnum` and
  `TestAlgorithmFamily17`, so registry drift fails loudly at refresh time
  rather than silently emitting values the served schema rejects.
- When updating a schema, refresh the upstream commit link and sha256 here.
