# cdxtest fixtures — provenance

Test key material for the `internal/cdxprops` conversion tests. All of it is
throwaway: generated locally, never used for anything, and safe to regenerate.
`.github/secret_scanning.yml` excludes this directory precisely because
CBOM-lens is a crypto scanner and its tests need real-shaped inputs.

Keep this directory small. The synthetic-DER sweep in
`internal/cdxprops/pem_oid_sweep_test.go` covers every registry OID without
fixture bytes, so a new file is only justified when it anchors something
synthetic DER cannot: a real generator's encoding choices, a real signature, or
a real parse failure.

## Post-quantum fixtures

| File | Algorithm | Purpose |
| --- | --- | --- |
| `ml-dsa-65-private-key.pem` | ML-DSA-65 | PKCS#8 private key |
| `ml-dsa-65-public-key.pem` | ML-DSA-65 | SPKI public key |
| `ml-dsa-65-cert.pem` | ML-DSA-65 | self-signed certificate |
| `ml-dsa-65-malformed-private-key.pem` | ML-DSA-65 | truncated DER, negative path |
| `slh-dsa-sha2-128s-private-key.pem` | SLH-DSA-SHA2-128s | PKCS#8 private key |
| `slh-dsa-sha2-128s-public-key.pem` | SLH-DSA-SHA2-128s | SPKI public key |
| `slh-dsa-sha2-128s-cert.pem` | SLH-DSA-SHA2-128s | self-signed certificate |
| `ml-kem-768-private-key.pem` | ML-KEM-768 | PKCS#8 private key |
| `ml-kem-768-public-key.pem` | ML-KEM-768 | SPKI public key |
| `ml-kem-768-cert.pem` | ML-KEM-768 key, ML-DSA-65 signature | KEM certificate |

### Source and licence

Generated locally with **OpenSSL 3.5.3 (16 Sep 2025)**, which implements
ML-DSA, ML-KEM and SLH-DSA in its default provider. Nothing is copied from a
third-party repository, so no upstream licence applies; these files are covered
by this repository's licence.

The SLH-DSA and ML-KEM encodings were cross-checked against the standards
rather than trusted:

- `slh-dsa-sha2-128s-public-key.pem` SPKI `BIT STRING` is 33 bytes = 1
  unused-bits octet + **32**, matching the public key size in FIPS 205 Table 2
  and RFC 9909 App. B.
- `slh-dsa-sha2-128s-cert.pem` signature `BIT STRING` is 7857 bytes = 1 + **7856**,
  matching the SLH-DSA-SHA2-128s signature size in the same tables.
- `ml-kem-768-public-key.pem` SPKI `BIT STRING` is 1185 bytes = 1 + **1184**,
  matching the ML-KEM-768 encapsulation key size in FIPS 203 Table 3.
- The SPKI algorithm OIDs are `2.16.840.1.101.3.4.3.20` (SLH-DSA-SHA2-128s)
  and `2.16.840.1.101.3.4.4.2` (ML-KEM-768), matching the NIST CSOR
  registrations.

RFC 9909 App. C publishes its own SLH-DSA-SHA2-128s example public key,
private key and certificate. They are interchangeable with these; a locally
generated set was preferred only to keep every fixture under one provenance
story.

### Regeneration

```sh
cd internal/cdxprops/cdxtest/testdata

# SLH-DSA-SHA2-128s: private key, public key, self-signed certificate
openssl genpkey -algorithm SLH-DSA-SHA2-128s -out slh-dsa-sha2-128s-private-key.pem
openssl pkey -in slh-dsa-sha2-128s-private-key.pem -pubout \
  -out slh-dsa-sha2-128s-public-key.pem
openssl req -new -x509 -key slh-dsa-sha2-128s-private-key.pem -days 7305 \
  -subj "/CN=cbom-lens SLH-DSA-SHA2-128s test/O=CBOM-lens test fixtures" \
  -out slh-dsa-sha2-128s-cert.pem

# ML-KEM-768: private key and public key
openssl genpkey -algorithm ML-KEM-768 -out ml-kem-768-private-key.pem
openssl pkey -in ml-kem-768-private-key.pem -pubout -out ml-kem-768-public-key.pem

# ML-KEM-768 certificate. A KEM cannot sign, so it cannot self-sign and cannot
# produce a CSR either; -force_pubkey installs the KEM key into a certificate
# signed by a separate ML-DSA-65 CA. The CA key and certificate are scratch
# files and are deliberately not committed.
openssl genpkey -algorithm ML-DSA-65 -out /tmp/ca-ml-dsa-65-key.pem
openssl req -new -x509 -key /tmp/ca-ml-dsa-65-key.pem -days 7305 \
  -subj "/CN=cbom-lens test CA (ML-DSA-65)/O=CBOM-lens test fixtures" \
  -out /tmp/ca.pem
openssl x509 -new -force_pubkey ml-kem-768-public-key.pem \
  -CA /tmp/ca.pem -CAkey /tmp/ca-ml-dsa-65-key.pem -days 7305 \
  -subj "/CN=cbom-lens ML-KEM-768 test/O=CBOM-lens test fixtures" \
  -out ml-kem-768-cert.pem
```

`ml-dsa-65-malformed-private-key.pem` is the first 40 DER bytes of
`ml-dsa-65-private-key.pem`, re-wrapped in a `PRIVATE KEY` PEM envelope. The
outer `SEQUENCE` header still advertises the full length, so the PEM decoder
succeeds and ASN.1 parsing then fails, which is the path under test:

```sh
python3 - <<'PY'
import base64, textwrap
b64 = ''.join(l for l in open('ml-dsa-65-private-key.pem')
              if not l.startswith('-----'))
der = base64.b64decode(b64)[:40]
body = '\n'.join(textwrap.wrap(base64.b64encode(der).decode(), 64))
open('ml-dsa-65-malformed-private-key.pem', 'w').write(
    '-----BEGIN PRIVATE KEY-----\n' + body + '\n-----END PRIVATE KEY-----\n')
PY
```

Regenerating any file changes its content hash, and component BOMRefs are
content hashes, so expect `internal/cdxprops` assertions that pin a ref or a
`MLDSA65PublicKeyHash`-style digest to need updating too.

## Deliberately absent

Fixtures were skipped where they would add bytes without adding coverage. See
`docs/pqc-support.md` for the reasoning per algorithm.

- **The other 11 SLH-DSA parameter sets, ML-DSA-44, ML-DSA-87, ML-KEM-512 and
  ML-KEM-1024.** All reached through the same `AlgorithmIdentifier` parse as
  the sets above; the synthetic-DER sweep covers every one of their OIDs.
- **XMSS, XMSS-MT, HSS-LMS.** OpenSSL 3.5.3 cannot generate them. Their OIDs
  are covered by the sweep.
- **HQC.** No OID is assigned, so there is nothing to detect and no fixture to
  generate. Not in the registry.
