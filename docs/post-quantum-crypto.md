# Post-Quantum Cryptography Support in CBOM-Lens

## 1. Lack of PQC Algorithms in Go Standard Library

The Go standard library does **not** currently support post-quantum cryptographic (PQC) algorithms. This means that widely recognized PQC schemes, such as ML-DSA (CRYSTALS-Dilithium), ML-KEM (Kyber), and others, are not available out-of-the-box for key generation, signing, or encryption in Go.

At the time of writing, the only post-quantum algorithm supported by the Go standard library is **ML-KEM-768**. For more details, see the [crypto/mlkem documentation](https://pkg.go.dev/crypto/mlkem@go1.25.5).

## 2. Using github.com/cloudflare/circl for PQC

To address this limitation, the project integrates the [github.com/cloudflare/circl](https://github.com/cloudflare/circl) library. CIRCL provides implementations of several post-quantum algorithms, enabling Go applications to use PQC for cryptographic operations such as key management and digital signatures.

#### 3. Supported ML-DSA Key Types

Currently, the following ML-DSA parameter sets are supported for both public and private keys:
- **ML-DSA-44**
- **ML-DSA-65**
- **ML-DSA-87**

These correspond to the CRYSTALS-Dilithium signature scheme at different security levels.

#### 4. Work in Progress

Support for post-quantum cryptography in this project is **work in progress**. Additional algorithms, features, and integration improvements are planned. Users should expect ongoing updates and are encouraged to provide feedback or contribute.

