# Upstream conformance fixtures

Copied verbatim from [`CycloneDX/specification`](https://github.com/CycloneDX/specification)
at commit `fac1ff6`, path `tools/src/test/resources/1.7/`. Apache-2.0, as is the
specification repository.

These are the specification's **own** examples of valid 1.7 cryptography
documents. They exist here as a *positive control* on the vendored schema set:
`TestValidator_AcceptsUpstreamConformanceFixtures` requires that all of them
validate.

Without this control, the validator tests only ever check documents CBOM-Lens
produced plus a hand-written invalid case. A subtly wrong schema snapshot, or a
`$ref` registered under the wrong URI so that a subschema silently never loads,
would leave every one of those tests passing — a validator that accepts
everything looks identical to a correct one until something external is fed to
it.

Do not edit these files. Refresh them from upstream when the vendored schema
snapshot is refreshed, and record the new commit here.
