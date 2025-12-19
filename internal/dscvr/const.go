package dscvr

import (
	"net/http"
)

const (
	// constants related to czertainly core attribute for passing cbom-lens configuration
	lensConfigurationAttrUUID        = "eb87e85b-297c-44f9-8f69-eebc86bf7c65"
	lensConfigurationAttrName        = "cbom_lens_scan_configuration"
	lensConfigurationAttrType        = "data"
	lensConfigurationAttrContentType = "codeblock"

	// constants related to czertainly core attribute for passing cbom-lens configuration
	lensConfigurationInfoAttrUUID        = "12045366-d686-4d46-a563-e02deb23ca7f"
	lensConfigurationInfoAttrName        = "cbom_lens_scan_configuration_info"
	lensConfigurationInfoAttrType        = "info"
	lensConfigurationInfoAttrContentType = "string"

	// constants related to czertainly core meta attribute for passing upload result json
	lensResultMetadataUploadKeyAttrUUID = "8895b0c5-d16b-4c85-991c-be9156c59e8d"
	lensResultMetadataUploadKeyAttrName = "cbom_lens_result_upload_json"

	// constants related to czertainly core meta attribute for passing repository get uri
	lensResultMetadataURIAttrUUID = "a29d6d07-17ab-4211-bc66-6c95f9e38842"
	lensResultMetadataURIAttrName = "cbom_lens_result_repository_uri"

	// constants related to czertainly core meta attribute for passing result in case of failure
	lensResultMetadataFailureReasonAttrUUID = "429d078c-73d1-445a-bf48-606509a3619e"
	lensResultMetadataFailureReasonAttrName = "cbom_lens_result_string"

	functionalGroupCode = "discoveryProvider"
)

const lensConfigurationInfoData = `
The CBOM-Lens configuration supports multiple discovery sources to scan and analyze software components:

**Filesystem Scanning** - Scans local file paths for software artifacts. When enabled, you can specify one or more directory paths to scan. If no paths are provided, the current working directory is used by default.

**Container Scanning** - Discovers components from container daemons (Docker/Podman). Supports multiple daemon connections, each configured with:
- Daemon type (docker or podman)
- Connection endpoint (e.g., unix:///var/run/docker.sock, supports environment variables)
- Optional image filters (if empty, all images are discovered)
- Custom name identifier for each daemon connection

**Port Scanning** - Performs network port scanning using nmap to discover running services. Configuration includes:
- Custom nmap binary path (uses $PATH by default)
- Port specification: single ports, ranges, or comma-separated lists (default: full range 1-65535)
- IPv4/IPv6 protocol selection (both enabled by default)

**Output Configuration** - Common settings across all scanners:
- Verbose logging toggle
- Log destination (stderr, stdout, discard, or file path)

**CBOM Generation** - Configures CycloneDX BOM output version (default 1.6) and optional extensions. For example czertainly extension injects CZERTAINLY specific properties to the CBOM.

All scanning modules (filesystem, containers, ports) are disabled by default and must be explicitly enabled in the configuration.
`

type EndpointDefinition struct {
	Path   string
	Method string
}

func DiscoveryRegisterEndpoint() EndpointDefinition {
	return EndpointDefinition{
		Path:   "/v1/connector/register",
		Method: http.MethodPost,
	}
}

func DiscoveryProviderEndpoints() map[string]EndpointDefinition {
	return map[string]EndpointDefinition{
		"checkHealth": {
			Path:   "/v1/health",
			Method: http.MethodGet,
		},
		"listSupportedFunctions": {
			Path:   "/v1",
			Method: http.MethodGet,
		},
		"listAttributeDefinitions": {
			Path:   "/v1/{functionalGroup}/{kind}/attributes",
			Method: http.MethodGet,
		},
		"validateAttributes": {
			Path:   "/v1/{functionalGroup}/{kind}/attributes/validate",
			Method: http.MethodPost,
		},
		"deleteDiscovery": {
			Path:   "/v1/{functionalGroup}/discover/{uuid}",
			Method: http.MethodDelete,
		},
		"discoverCertificate": {
			Path:   "/v1/{functionalGroup}/discover",
			Method: http.MethodPost,
		},
		"getDiscovery": {
			Path:   "/v1/{functionalGroup}/discover/{uuid}",
			Method: http.MethodPost,
		},
	}
}
