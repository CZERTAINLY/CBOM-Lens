# Scanning Use Cases & Best Practices

This document describes common ways to use CBOM-Lens to build and maintain an inventory of cryptographic assets.

For configuration details, see the [Configuration guide](configuration.md) and the [Configuration reference](config.md).

---

## 1. Host filesystem inventory

Use filesystem scans to:

- Discover certificates and keys stored on servers.
- Identify secrets (passwords, tokens) committed to configuration directories.

Typical pattern:

```yaml
filesystem:
  enabled: true
  paths:
    - /etc/ssl
    - /var/lib/myapp
```

Run in `manual` mode from a CI/CD pipeline or in `timer` mode as a periodic host scan.

---

## 2. Container image inventory

Scan container images to:

- Identify certificates and keys baked into images.
- Detect secrets stored in container images before deployment.

Example:

```yaml
containers:
  enabled: true
  config:
    - host: ${DOCKER_HOST}
      images:
        - docker.io/library/nginx:latest
        - docker.io/library/alpine:3.22.1
```

Best practices:

- Integrate into image build pipelines to catch issues before images are pushed or deployed.
- Maintain a list of critical images to scan regularly.

---

## 3. Network service inventory (ports)

Use port scans to:

- Identify exposed TLS and SSH endpoints.
- Build a map of network-facing cryptographic material.

Example (simplified):

```yaml
ports:
  enabled: true
  ipv4: true
  ipv6: false
```

Best practices:

- Run from trusted network locations with visibility into relevant hosts.
- Start with limited port ranges and expand as needed.
- Coordinate with network/security teams to avoid surprises from nmap traffic.

---

## 4. Combining sources

CBOM-Lens is particularly powerful when you combine filesystem, containers, and ports:

- Filesystem scans show what is **stored** on hosts.
- Container scans show what is **packaged** into images.
- Port scans show what is **exposed** on the network.

Because CBOM-Lens uses stable, content-based `bom-ref` identifiers, the same cryptographic asset discovered in multiple places (e.g., a certificate on disk, in an image, and on a live port) will have the same `bom-ref`, enabling correlation.

---

## 5. Integrating into security processes

Examples:

- **Change control** – generate CBOMs before and after deployments to track changes in cryptographic material.
- **Compliance** – regularly run timed scans to demonstrate continuous visibility into certificates and keys.
- **Incident response** – quickly scan affected systems and images to locate vulnerable or compromised cryptographic assets.

Use `timer` mode for continuous inventory and `manual` mode for ad-hoc investigations.

---

## 6. Interpreting CBOM output

For guidance on how CBOMs represent cryptographic assets, algorithms, and references, see:

- [CBOM output format](cbom-format.md) – CBOM structure, `bom-ref` semantics, and examples.

---

## 7. Next steps

- Configure scans for your environment: see the [Configuration guide](configuration.md).
- Automate scans with timers or discovery mode: see [Scanning modes & scheduling](scanning-modes.md) and [CZERTAINLY & CBOM-Repository integration](integration-czertainly.md).
- Understand CBOM data in depth: see [CBOM output format](cbom-format.md).
