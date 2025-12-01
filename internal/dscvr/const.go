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

	// constants related to czertainly core meta attribute for passing upload key
	lensResultMetadataUploadKeyAttrUUID = "8895b0c5-d16b-4c85-991c-be9156c59e8d"
	lensResultMetadataUploadKeyAttrName = "cbom_lens_result_upload_key"

	// constants related to czertainly core meta attribute for passing result
	lensResultMetadataFailureReasonAttrUUID = "429d078c-73d1-445a-bf48-606509a3619e"
	lensResultMetadataFailureReasonAttrName = "cbom_lens_result_string"

	functionalGroupCode = "discoveryProvider"
)

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
