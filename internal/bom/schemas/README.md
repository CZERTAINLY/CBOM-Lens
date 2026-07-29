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

## Notes

- `bom-1.6.schema.json` declares `$id: http://cyclonedx.org/schema/bom-1.6.schema.json`
  and references `spdx.schema.json` and `jsf-0.82.schema.json` via relative
  `$ref`s, which resolve to `http://cyclonedx.org/schema/spdx.schema.json` and
  `http://cyclonedx.org/schema/jsf-0.82.schema.json`. The vendored subschemas
  carry exactly those `$id`s.
- When updating a schema, refresh the upstream commit link and sha256 here.
