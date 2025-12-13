# PQC support

`CBOM-Lens` is written in Go, which does not support PQC algorithm yet. The tool fallbacks to parsing the ASN.1 structure in cases it can't use stdlib to do so.

This works for PEM format and x509.Certificates.

- **2.16.840.1.101.3.4.3.17**: `crypto/algorithm/ml-dsa-44`
- **2.16.840.1.101.3.4.3.18**: `crypto/algorithm/ml-dsa-65`
- **2.16.840.1.101.3.4.3.19**: `crypto/algorithm/ml-dsa-87`
- **2.16.840.1.101.3.4.3.20**: `crypto/algorithm/slh-dsa-sha2-128s`
- **2.16.840.1.101.3.4.3.21**: `crypto/algorithm/slh-dsa-sha2-128f`
- **2.16.840.1.101.3.4.3.22**: `crypto/algorithm/slh-dsa-sha2-192s`
- **2.16.840.1.101.3.4.3.23**: `crypto/algorithm/slh-dsa-sha2-192f`
- **2.16.840.1.101.3.4.3.24**: `crypto/algorithm/slh-dsa-sha2-256s`
- **2.16.840.1.101.3.4.3.25**: `crypto/algorithm/slh-dsa-sha2-256f`
- **2.16.840.1.101.3.4.3.26**: `crypto/algorithm/slh-dsa-shake-128s`
- **2.16.840.1.101.3.4.3.27**: `crypto/algorithm/slh-dsa-shake-128f`
- **2.16.840.1.101.3.4.3.28**: `crypto/algorithm/slh-dsa-shake-192s`
- **2.16.840.1.101.3.4.3.29**: `crypto/algorithm/slh-dsa-shake-192f`
- **2.16.840.1.101.3.4.3.30**: `crypto/algorithm/slh-dsa-shake-256s`
- **2.16.840.1.101.3.4.3.31**: `crypto/algorithm/slh-dsa-shake-256f`
- **1.3.6.1.5.5.7.6.34**: `crypto/algorithm/xmss-hashsig`
- **1.3.6.1.5.5.7.6.35**: `crypto/algorithm/xmssmt-hashsig`
- **1.2.840.113549.1.9.16.3.17**: `crypto/algorithm/hss-lms-hashsig`
- **1.3.9999.6.1.1**: `crypto/algorithm/hqc-128`
- **1.3.9999.6.1.2**: `crypto/algorithm/hqc-192`
- **1.3.9999.6.1.3**: `crypto/algorithm/hqc-256`
