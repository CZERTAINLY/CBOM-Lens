# PQC support

Go's standard library does not parse post-quantum keys, so CBOM-Lens falls back
to reading the ASN.1 `AlgorithmIdentifier` directly and looking the OID up in a
hand-maintained registry (`internal/cdxprops/algorithm.go`). This works for PEM
files (`PUBLIC KEY`, `PRIVATE KEY`), for X.509 certificates, and for certificate
requests — a request's `subjectPublicKeyInfo` is the same structure, and Go
parses such a request successfully while leaving its key nil.

Because the identifier is all we get, **everything reported comes from the OID
alone**. Where a property is a function of a parameter set carried inside the
key rather than of the OID, CBOM-Lens omits it rather than guessing.

That governs what is reported, not whether a key is reported at all: the OID
establishes that the algorithm is referenced here, and the key body has to hold
up on its own before a key asset is emitted. See
[Key body validation](#key-body-validation).

Every value in the registry is transcribed from a primary source and pinned by
`internal/cdxprops/algorithm_registry_test.go`, whose expectation table is
written from the standards documents rather than copied from the registry.

## Recognised algorithms

### ML-DSA — FIPS 204, OIDs from RFC 9881

| OID | Name | Parameter set | NIST category | Classical bits |
| --- | --- | --- | --- | --- |
| `2.16.840.1.101.3.4.3.17` | ML-DSA-44 | 44 | 2 | 128 |
| `2.16.840.1.101.3.4.3.18` | ML-DSA-65 | 65 | 3 | 192 |
| `2.16.840.1.101.3.4.3.19` | ML-DSA-87 | 87 | 5 | 256 |

Sizes (private / public / signature, bytes) from FIPS 204 Table 2:
2560/1312/2420, 4032/1952/3309, 4896/2592/4627.

ML-DSA-44 is reported as **category 2**, per FIPS 204 Table 1. It is not
category 1. FIPS 204 §3.6.1 reduces it to category 1 only when the signer's key
generation used an approved RBG with less than 192 bits of security, which is
not observable from a key or certificate.

### SLH-DSA — FIPS 205, OIDs from the NIST CSOR

| OID | Name | NIST category | Classical bits | Public | Private | Signature |
| --- | --- | --- | --- | --- | --- | --- |
| `…3.4.3.20` | SLH-DSA-SHA2-128S | 1 | 128 | 32 | 64 | 7856 |
| `…3.4.3.21` | SLH-DSA-SHA2-128F | 1 | 128 | 32 | 64 | 17088 |
| `…3.4.3.22` | SLH-DSA-SHA2-192S | 3 | 192 | 48 | 96 | 16224 |
| `…3.4.3.23` | SLH-DSA-SHA2-192F | 3 | 192 | 48 | 96 | 35664 |
| `…3.4.3.24` | SLH-DSA-SHA2-256S | 5 | 256 | 64 | 128 | 29792 |
| `…3.4.3.25` | SLH-DSA-SHA2-256F | 5 | 256 | 64 | 128 | 49856 |
| `…3.4.3.26` | SLH-DSA-SHAKE-128S | 1 | 128 | 32 | 64 | 7856 |
| `…3.4.3.27` | SLH-DSA-SHAKE-128F | 1 | 128 | 32 | 64 | 17088 |
| `…3.4.3.28` | SLH-DSA-SHAKE-192S | 3 | 192 | 48 | 96 | 16224 |
| `…3.4.3.29` | SLH-DSA-SHAKE-192F | 3 | 192 | 48 | 96 | 35664 |
| `…3.4.3.30` | SLH-DSA-SHAKE-256S | 5 | 256 | 64 | 128 | 29792 |
| `…3.4.3.31` | SLH-DSA-SHAKE-256F | 5 | 256 | 64 | 128 | 49856 |

The `…` prefix is `2.16.840.1.101.3`. Sizes from RFC 9909 App. B Table 1,
cross-checked against FIPS 205 Table 2. Classical levels from RFC 9909 §1: the
three security levels are "at least as secure as a generic block cipher of 128,
192, or 256 bits".

### ML-KEM — FIPS 203, OIDs from the NIST CSOR

| OID | Name | NIST category | Classical bits | Encaps. key | Decaps. key | Ciphertext |
| --- | --- | --- | --- | --- | --- | --- |
| `2.16.840.1.101.3.4.4.1` | ML-KEM-512 | 1 | 128 | 800 | 1632 | 768 |
| `2.16.840.1.101.3.4.4.2` | ML-KEM-768 | 3 | 192 | 1184 | 2400 | 1088 |
| `2.16.840.1.101.3.4.4.3` | ML-KEM-1024 | 5 | 256 | 1568 | 3168 | 1568 |

Sizes from FIPS 203 Table 3; categories from FIPS 203 §8; classical levels from
FIPS 203 Table 2 ("required RBG strength"). FIPS 203 assigns no OIDs; those come
from the CSOR, where `kems ::= { nistAlgorithms 4 }`.

ML-KEM components carry `primitive: kem` and
`cryptoFunctions: [decapsulate, encapsulate]`. Being a KEM, ML-KEM has no
signature, so `…:pqc:signature_size` is never emitted for it; a
`…:pqc:ciphertext_size` property is emitted instead. The encapsulation key size
is reported as `…:pqc:public_key_size` and the decapsulation key size as
`…:pqc:private_key_size`.

### Stateful hash-based signatures — SP 800-208

| OID | Name | Source |
| --- | --- | --- |
| `1.3.6.1.5.5.7.6.34` | XMSS | RFC 9802 (`id-alg-xmss-hashsig`) |
| `1.3.6.1.5.5.7.6.35` | XMSS-MT | RFC 9802 (`id-alg-xmssmt-hashsig`) |
| `1.2.840.113549.1.9.16.3.17` | HSS-LMS | RFC 9708 (`id-alg-hss-lms-hashsig`) |

Two deliberate omissions here:

- **No `nistQuantumSecurityLevel`.** SP 800-208 assigns no NIST security
  category to stateful hash-based signatures. The field is omitted, not set to
  0 — CycloneDX defines 0 as "meets none of the categories", which is a claim no
  NIST document makes about these schemes.
- **No key or signature sizes.** RFC 9802 §2: the public key and signature
  values themselves identify the hash function and tree height. The sizes belong
  to a parameter set inside the key, not to the OID we matched, so they are not
  reported.

`classicalSecurityLevel: 256` is reported for all three and assumes the n=32
(SHA-256) parameter families. This is an approximation for the same reason: the
OID does not carry the parameter set.

## Not supported

Listed explicitly, so that absence reads as a decision rather than an oversight.

| Algorithm | Why not |
| --- | --- |
| **HQC** | No assigned OID. The NIST CSOR has no HQC arc (FIPS 207 unpublished), and `open-quantum-safe/oqs-provider` records the OID of every HQC variant as NULL. There is nothing to match on. |
| **FN-DSA (FALCON)** | Not standardised; no assigned OID. |
| **Classic McEliece** | No assigned OID. |
| **Hybrid / composite keys** | Not modelled. The CycloneDX-idiomatic form is a `combiner`-primitive component plus the two constituents joined by `dependsOn`; nothing emits that yet. |
| **PQ key exchange in TLS and SSH** | Not detected. For example `X25519MLKEM768` (TLS group `0x11EC`, OpenSSH 10.0's default `mlkem768x25519-sha256`) is not recognised as post-quantum. |

A caution on `1.3.9999.6.1.1`, `.2` and `.3`: these are sometimes taken for
HQC-128/192/256, but in `oqs-provider`'s `oqs-template/generate.yml` they belong
to SPHINCS+-Haraka-128f-robust (NIST Round 3) and its p256 and rsa3072 hybrids.
CBOM-Lens does not match them, so such a key yields an `unsupported fallback
oid` miss rather than a confidently wrong HQC component. A test keeps them out
of the registry.

## Primitives on the certificate path

A certificate's key is reported with its own primitive: `kem` for ML-KEM, `pke`
for an RSA key whose KeyUsage is keyEncipherment only, `signature` otherwise.
For ML-KEM this is the only way the primitive can be known — no KeyUsage
inspection yields it, so it comes from the registry entry.

A component's `primitive` is fixed before the component is hashed into its
BOMRef, which is what lets a reference describe its own contents.
`TestCertHitToComponents_BOMRefsMatchContents` enforces that generally: it
re-hashes every emitted `crypto/algorithm/` component and requires the result to
reproduce its BOMRef, so mutating a component after hashing fails immediately.

## Key body validation

An OID says which algorithm is present. It does not say that the bytes under it
are a key of that algorithm, and nothing downstream can tell afterwards: a
component built from an OID and twenty-four bytes of noise validates against the
schema and reads as a confident report. So a body that cannot be a key of the
algorithm its OID names yields the algorithm component and **no key component**,
with a `Warn` line naming the algorithm, the OID, the body length and the
reason.

**Private keys (PKCS#8).** The block must parse with nothing trailing the
`PrivateKeyInfo`, and its version must be 0 (RFC 5208) or 1 (RFC 5958's
`OneAsymmetricKey`, which is what carries a `publicKey`). The `privateKey` body
is then matched against the CHOICE that RFC 9881 §6 (ML-DSA) and RFC 9935 §6
(ML-KEM) define, rather than against a length bound — one algorithm has several
legal body lengths two orders of magnitude apart, so no single bound accepts all
of them without also accepting noise:

| Encoding | ML-DSA-65 body, header ‖ content (total) | Applies to |
| --- | --- | --- |
| `[0] OCTET STRING` of the seed | `80 20` ‖ 32 (34) | ML-DSA, ML-KEM |
| `SEQUENCE { OCTET STRING seed, OCTET STRING expandedKey }`, two elements and no third | `30 82 0F E6` ‖ 4070 (4074) | ML-DSA, ML-KEM |
| `OCTET STRING` of the expanded key | `04 82 0F C0` ‖ 4032 (4036) | all sized schemes |
| the expanded key raw, with no wrapper | — ‖ 4032 (4032) | all sized schemes |

Seed-only is the RECOMMENDED form, and is what `openssl genpkey -provparam
ml-dsa.output_formats=seed-only` and Node.js write, so a floor at the expanded
size would drop real keys; a floor at the seed size would accept 32 bytes of
noise as a full ML-DSA-65 key. The raw alternative is not in the RFC, but a
producer that skips the wrapper still wrote a real key. SLH-DSA has no seed
alternative and its private key carries no inner structure, so only the last two
rows apply to it — a 64-byte SLH-DSA-SHA2-128S body is the whole key.

**Public keys (SPKI).** The `subjectPublicKeyInfo` must parse with nothing
trailing it; its BIT STRING must declare a `BitLength` equal to
`len(Bytes) * 8`, since none of these schemes define a key with unused trailing
bits; and it must hold exactly the byte count the registry states for that
parameter set.

**XMSS, XMSS-MT and HSS-LMS are exempt from both byte counts.** SP 800-208 puts
the parameter set inside the key rather than in the OID, so there is no size to
compare against and no defined body encoding to match. Only an empty body is
rejected — and, for a public key, the `BitLength` check, which is a property of
the encoding rather than of the parameter set. Dropping a real key is the worse
error here.

## Private-key references

A classical private key takes its `bom-ref` from the digest of its own public
key, which keeps secret material out of the reference and is what makes the two
halves of one keypair correlatable within the document.

A post-quantum private key cannot do that. The PKCS#8 block yields the version,
the `privateKeyAlgorithm` and the body; recovering the public half from a seed
means running key generation, which Go has no post-quantum support for. So the
reference hashes the private DER instead, and a post-quantum private key pairs
with its public counterpart through `algorithmRef` — by algorithm, not by
keypair. Do not read the classical invariant into the shared
`crypto/private_key/` prefix.

This is a deliberate trade-off, and it is the only reference in a CBOM-Lens
document derived from secret material. The document carries a digest and never
the key, and it discloses nothing to anyone who does not already hold the key.
But the derivation is reproducible, and the UUIDv5 rewrite described in
[CBOM output format](cbom-format.md) hides the digest without breaking it, so
someone holding a candidate key can confirm from the document that it was
scanned and read `evidence.occurrences` for where. Content addressing is what
buys the other side: the same key found at two paths dedupes to one asset, where
a location-derived reference would move whenever the scan root changed.

RFC 5958's optional `publicKey [1]` field would close this where a producer
emits it — the public half is then in the block, and a `SubjectPublicKeyInfo`
could be reconstructed from it and the algorithm. Tracked as follow-up work.

## Test coverage

- `algorithm_registry_test.go` — expectation table transcribed from the
  standards; compares every registry field, both key sets in both directions,
  and the emitted component shape.
- `pem_oid_sweep_test.go` — drives all 21 registry OIDs through the real
  `unsupportedPKIX` and `unsupportedPKCS8PrivateKey` parse paths using synthetic
  DER, so no per-parameter-set fixture is needed. Includes negative cases:
  unregistered OID, truncated DER, empty input, and a bare
  `AlgorithmIdentifier`.
- `pqc_pipeline_test.go` — real key files through the PEM scanner, converter,
  Builder and emitter, validated against the CycloneDX 1.6 schema and asserted
  on by content.
- `ml_kem_test.go` — the ML-KEM key paths specifically.

Fixtures live in `internal/cdxprops/cdxtest/testdata`; see the README there for
provenance and regeneration commands. Only ML-DSA-65, SLH-DSA-SHA2-128s and
ML-KEM-768 have real key fixtures. The other parameter sets are covered by the
OID sweep, XMSS/XMSS-MT/HSS-LMS cannot be generated by OpenSSL 3.5.3, and HQC
has no OID to generate a key for.

The shared 1.6 golden corpus (`internal/bom/testdata/golden/corpus-1.6.json`)
contains no post-quantum material; PQC coverage comes from the tests above
instead. Adding a PQC detection to the corpus is tracked as follow-up work.
