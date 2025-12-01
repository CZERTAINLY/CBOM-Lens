package dscvr

import (
	"encoding/base64"
	"fmt"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	"go.yaml.in/yaml/v4"
)

type checkHealthResponse struct {
	Status      string  `json:"status"`
	Description *string `json:"description,omitempty"`
}

type listSupportedFunctionsResponse []supportedFunction

type listAttributeDefinitionsResponse []attrCodeblock

type discoverCertificateRequest struct {
	Name       string          `json:"name"`
	Kind       string          `json:"kind"`
	Attributes []attrCodeblock `json:"attributes"`
}

type discoverCertificateResponse struct {
	UUID            string `json:"uuid"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	CertificateData []any  `json:"certificateData"`
	Meta            []any  `json:"meta"`
}

type getDiscoveryRequest struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	PageNumber   int    `json:"pageNumber"`
	ItemsPerPage int    `json:"itemsPerPage"`
}

type getDiscoveryResponse struct {
	UUID                        string                 `json:"uuid"`
	Name                        string                 `json:"name"`
	Status                      string                 `json:"status"`
	CertificateData             []any                  `json:"certificateData"`
	TotalCertificatesDiscovered int                    `json:"totalCertificatesDiscovered"`
	Meta                        []getDiscoveryMetaItem `json:"meta"`
}

type getDiscoveryMetaItem struct {
	Version     int    `json:"version"`
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Description string `json:"description"`

	Content     []any          `json:"content"`
	Type        string         `json:"type"`
	ContentType string         `json:"contentType"`
	Properties  metaProperties `json:"properties"`
}

type generalErrMsgResp struct {
	Message string `json:"message"`
}

type registerConnectorRequest struct {
	Name             string `json:"name"`
	Url              string `json:"url"`
	AuthType         string `json:"authType"`
	AuthAttributes   []any  `json:"authAttributes"`
	CustomAttributes []any  `json:"customAttributes"`
}

type metaItemContentString struct {
	Data string `json:"data"`
}

type metaItemContentCodeblock struct {
	Data metaItemContentCodeblockItem `json:"data"`
}

type metaItemContentCodeblockItem struct {
	Language string `json:"language"`
	Code     string `json:"code"`
}

type metaProperties struct {
	Label   string `json:"label"`
	Visible bool   `json:"visible"`
}

type supportedFunction struct {
	FuncGroupCode string                      `json:"functionGroupCode"`
	Kinds         []string                    `json:"kinds"`
	Endpoints     []supportedFunctionEndpoint `json:"endPoints"`
}

type supportedFunctionEndpoint struct {
	UUID     *string `json:"uuid"`
	Name     string  `json:"name"`
	Context  string  `json:"context"`
	Method   string  `json:"method"`
	Required bool    `json:"required"`
}

type attrCodeblock struct {
	Version     *int                   `json:"version,omitempty"`
	UUID        string                 `json:"uuid"`
	Name        string                 `json:"name"`
	Description *string                `json:"description,omitempty"`
	Type        *string                `json:"type,omitempty"`
	ContentType *string                `json:"contentType,omitempty"`
	Content     []attrCodeblockContent `json:"content"`
	Properties  *attrProperties        `json:"properties,omitempty"`
}

type attrCodeblockContent struct {
	Reference *string                  `json:"reference,omitempty"`
	Data      attrCodeblockContentData `json:"data"`
}

type attrCodeblockContentData struct {
	Code     string `json:"code"`
	Language string `json:"language"`
}

type attrProperties struct {
	Label   string `json:"label"`
	Visible bool   `json:"visible"`
}

func validateAttr(attrs []attrCodeblock) error {
	for _, cpy := range attrs {
		switch cpy.UUID {
		case lensConfigurationAttrUUID:
			if cpy.ContentType == nil {
				return fmt.Errorf("attribute uuid: %q, name: %q does not have 'ContentType' property defined", cpy.UUID, cpy.Name)
			}
			if *cpy.ContentType != lensConfigurationAttrContentType {
				return fmt.Errorf("attribute uuid: %q, name: %q does not have expected 'ContentType' property defined, expected: %q, actual, %q",
					cpy.UUID, cpy.Name, lensConfigurationAttrContentType, *cpy.ContentType)
			}
			if len(cpy.Content) != 1 {
				return fmt.Errorf("attribute uuid: %q, name: %q has unexpected number of items in `Content` array, expected: 1, actual: %d",
					cpy.UUID, cpy.Name, len(cpy.Content))
			}
			if cpy.Content[0].Data.Language != "yaml" {
				return fmt.Errorf("attribute uuid: %q, name: %q defines unexpected language, expected: 'yaml', actual: %q", cpy.UUID, cpy.Name, cpy.Content[0].Data.Language)
			}
			dd, err := base64.StdEncoding.DecodeString(cpy.Content[0].Data.Code)
			if err != nil {
				return fmt.Errorf("attribute uuid: %q, name: %q contains an unexpected base64 encoded value: %q: %s", cpy.UUID, cpy.Name, cpy.Content[0].Data.Code, err)
			}
			var m model.Scan
			err = yaml.Unmarshal(dd, &m)
			if err != nil {
				return fmt.Errorf("attribute uuid: %q, name: %q is not a valid yaml cbom-lens scan configuration: %s", cpy.UUID, cpy.Name, err)
			}

		default:
			return fmt.Errorf("unknown attribute uuid: %q name: %q", cpy.UUID, cpy.Name)
		}
	}
	return nil
}

func ptrString(v string) *string {
	return &v
}

func ptrInt(v int) *int {
	return &v
}
