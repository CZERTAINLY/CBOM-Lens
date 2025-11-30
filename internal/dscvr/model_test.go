package dscvr

import (
	"encoding/base64"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"
)

func TestValidateAttr(t *testing.T) {
	// Helper function to create valid scan config
	validScanConfig := model.Scan{
		Version: 0,
		Filesystem: model.Filesystem{
			Enabled: true,
			Paths:   []string{"/tmp"},
		},
		Containers: model.Containers{
			Enabled: false,
		},
		Ports: model.Ports{
			Enabled: false,
		},
		Service: model.ServiceFields{
			Verbose: false,
			Log:     "stderr",
		},
	}

	validYAML, err := yaml.Marshal(validScanConfig)
	require.NoError(t, err)
	validBase64 := base64.StdEncoding.EncodeToString(validYAML)

	tests := []struct {
		name    string
		attrs   []attrCodeblock
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid attribute",
			attrs: []attrCodeblock{
				{
					UUID:        seekerConfigurationAttrUUID,
					Name:        seekerConfigurationAttrName,
					ContentType: ptrString(seekerConfigurationAttrContentType),
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing ContentType",
			attrs: []attrCodeblock{
				{
					UUID:        seekerConfigurationAttrUUID,
					Name:        seekerConfigurationAttrName,
					ContentType: nil,
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "does not have 'ContentType' property defined",
		},
		{
			name: "wrong ContentType value",
			attrs: []attrCodeblock{
				{
					UUID:        seekerConfigurationAttrUUID,
					Name:        seekerConfigurationAttrName,
					ContentType: ptrString("json"),
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "does not have expected 'ContentType' property defined",
		},
		{
			name: "empty Content array",
			attrs: []attrCodeblock{
				{
					UUID:        seekerConfigurationAttrUUID,
					Name:        seekerConfigurationAttrName,
					ContentType: ptrString(seekerConfigurationAttrContentType),
					Content:     []attrCodeblockContent{},
				},
			},
			wantErr: true,
			errMsg:  "has unexpected number of items in `Content` array, expected: 1, actual: 0",
		},
		{
			name: "multiple Content items",
			attrs: []attrCodeblock{
				{
					UUID:        seekerConfigurationAttrUUID,
					Name:        seekerConfigurationAttrName,
					ContentType: ptrString(seekerConfigurationAttrContentType),
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "has unexpected number of items in `Content` array, expected: 1, actual: 2",
		},
		{
			name: "wrong language",
			attrs: []attrCodeblock{
				{
					UUID:        seekerConfigurationAttrUUID,
					Name:        seekerConfigurationAttrName,
					ContentType: ptrString(seekerConfigurationAttrContentType),
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "json",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "defines unexpected language, expected: 'yaml', actual: \"json\"",
		},
		{
			name: "invalid base64 encoding",
			attrs: []attrCodeblock{
				{
					UUID:        seekerConfigurationAttrUUID,
					Name:        seekerConfigurationAttrName,
					ContentType: ptrString(seekerConfigurationAttrContentType),
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     "not-valid-base64!@#$",
								Language: "yaml",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "contains an unexpected base64 encoded value",
		},
		{
			name: "invalid YAML structure",
			attrs: []attrCodeblock{
				{
					UUID:        seekerConfigurationAttrUUID,
					Name:        seekerConfigurationAttrName,
					ContentType: ptrString(seekerConfigurationAttrContentType),
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     base64.StdEncoding.EncodeToString([]byte("invalid: yaml: structure: [unclosed")),
								Language: "yaml",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "is not a valid yaml seeker scan configuration",
		},
		{
			name: "unknown UUID",
			attrs: []attrCodeblock{
				{
					UUID:        "unknown-uuid-1234",
					Name:        "unknown-attr",
					ContentType: ptrString(seekerConfigurationAttrContentType),
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "unknown attribute uuid",
		},
		{
			name:    "empty attributes slice",
			attrs:   []attrCodeblock{},
			wantErr: false,
		},
		{
			name: "multiple valid attributes",
			attrs: []attrCodeblock{
				{
					UUID:        seekerConfigurationAttrUUID,
					Name:        seekerConfigurationAttrName,
					ContentType: ptrString(seekerConfigurationAttrContentType),
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
					},
				},
				{
					UUID:        seekerConfigurationAttrUUID,
					Name:        seekerConfigurationAttrName,
					ContentType: ptrString(seekerConfigurationAttrContentType),
					Content: []attrCodeblockContent{
						{
							Data: attrCodeblockContentData{
								Code:     validBase64,
								Language: "yaml",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "nil attributes slice",
			attrs:   nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAttr(tt.attrs)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
