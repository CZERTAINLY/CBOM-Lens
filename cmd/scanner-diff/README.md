# scanner-diff

Runs both the zgrab and nmap port scanners against the same target and prints
a diff-like report showing where they agree and disagree on:

- open ports
- service detection (TLS, SSH, unknown)
- TLS cipher suites per protocol version
- server certificates (subject, SANs, expiry, issuer)
- SSH host keys (type, bit size, fingerprint)

Requires `nmap` to be installed and on `$PATH`.

## Usage

```
go run ./cmd/scanner-diff -host <hostname-or-ip> [flags]

Flags:
  -host   hostname or IP address to scan (required)
  -ports  ports to scan, e.g. 443 or 22,443 or 1-1024  (default: 22,443,8443)
  -sni    TLS SNI hostname (defaults to -host when it is a name, not an IP)
  -nmap   path to nmap binary (default: nmap)
```

## Output format

```
= <value>   both scanners agree
N <value>   nmap found this, zgrab did not
Z <value>   zgrab found this, nmap did not
! <detail>  present in both but values differ
```

> **SSH fingerprints**: nmap reports SHA-256 fingerprints; zgrab uses legacy
> MD5. The diff matches SSH keys by type rather than fingerprint, and prints
> both fingerprints side by side for reference.

---

## Test targets

### Modern / reference

```sh
# IANA reference — stable, minimal, single cert
go run ./cmd/scanner-diff -host example.com -ports 443

# GitHub — modern TLS + SSH on the same host
go run ./cmd/scanner-diff -host github.com -ports 22,443

# Cloudflare — TLS 1.3 preferred, HTTP/2, ECDSA cert
go run ./cmd/scanner-diff -host cloudflare.com -ports 443

# Mozilla — publishes its own TLS recommendations
go run ./cmd/scanner-diff -host www.mozilla.org -ports 443

# Wikipedia — ECDSA leaf cert, broad SAN list
go run ./cmd/scanner-diff -host www.wikipedia.org -ports 443

# Qualys SSL Labs — should practice what they grade
go run ./cmd/scanner-diff -host www.ssllabs.com -ports 443
```

### Weak / legacy TLS — badssl.com

Each subdomain of [badssl.com](https://badssl.com) is purpose-built to expose
a specific TLS misconfiguration.

```sh
# Expired certificate
go run ./cmd/scanner-diff -host expired.badssl.com -ports 443

# Self-signed certificate (no trusted CA)
go run ./cmd/scanner-diff -host self-signed.badssl.com -ports 443

# Wrong hostname in certificate
go run ./cmd/scanner-diff -host wrong.host.badssl.com -ports 443

# Incomplete certificate chain
go run ./cmd/scanner-diff -host incomplete-chain.badssl.com -ports 443

# SHA-1 intermediate — weak hash in chain
go run ./cmd/scanner-diff -host sha1-intermediate.badssl.com -ports 443

# RC4 cipher only (very weak, many clients refuse)
go run ./cmd/scanner-diff -host rc4.badssl.com -ports 443

# 3DES cipher only
go run ./cmd/scanner-diff -host 3des.badssl.com -ports 443

# TLS 1.0 only (no 1.2 or 1.3)
go run ./cmd/scanner-diff -host tls-v1-0.badssl.com -ports 1010

# TLS 1.1 only
go run ./cmd/scanner-diff -host tls-v1-1.badssl.com -ports 1011

# TLS 1.2 only (no 1.3)
go run ./cmd/scanner-diff -host tls-v1-2.badssl.com -ports 1012

# 2048-bit RSA key
go run ./cmd/scanner-diff -host rsa2048.badssl.com -ports 443

# 4096-bit RSA key
go run ./cmd/scanner-diff -host rsa4096.badssl.com -ports 443

# ECDSA 256-bit key
go run ./cmd/scanner-diff -host ecc256.badssl.com -ports 443

# ECDSA 384-bit key
go run ./cmd/scanner-diff -host ecc384.badssl.com -ports 443

# Revoked certificate
go run ./cmd/scanner-diff -host revoked.badssl.com -ports 443
```

### testssl.sh demo

```sh
# testssl.sh's own demo server — intentionally supports a wide range of suites
go run ./cmd/scanner-diff -host demo.testssl.sh -ports 443
```

### SSH endpoints

```sh
# GitHub SSH (also accepts SSH on port 443 for firewalled clients)
go run ./cmd/scanner-diff -host ssh.github.com -ports 22

# GitLab
go run ./cmd/scanner-diff -host gitlab.com -ports 22

# Bitbucket
go run ./cmd/scanner-diff -host bitbucket.org -ports 22
```

### IPv6

Add `-6` via nmap if forcing IPv6. The tool auto-detects IPv6 addresses.

```sh
# Cloudflare's public DNS over IPv6
go run ./cmd/scanner-diff -host 2606:4700:4700::1111 -ports 443

# Google's public DNS over IPv6
go run ./cmd/scanner-diff -host 2001:4860:4860::8888 -ports 443
```

---

## Known systematic differences

| Area | nmap | zgrab |
|------|------|-------|
| TLS 1.3 ciphers | enumerates all supported suites | returns one (single handshake) |
| SSH fingerprint | SHA-256 | MD5 (legacy) |
| TLS 1.2 cipher list | complete via script | limited to `knownTLS12Suites()` |
| Port scan method | SYN scan (needs root) or TCP connect | TCP connect only |
| Service detection | `-sV` deep probe | TLS/SSH heuristic only |
