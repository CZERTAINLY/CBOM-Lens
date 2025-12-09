package dscvr

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/dscvr/mock"
	"github.com/CZERTAINLY/CBOM-lens/internal/dscvr/store"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.yaml.in/yaml/v4"
)

func TestServer_checkHealth(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	w := httptest.NewRecorder()

	s.checkHealth(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var result checkHealthResponse
	err := json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)
	require.Equal(t, "ok", result.Status)
}

func TestServer_checkHealth_WrongMethod(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	req := httptest.NewRequest(http.MethodPost, "/v1/health", nil)
	w := httptest.NewRecorder()

	s.checkHealth(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestServer_listSupportedFunctions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	req := httptest.NewRequest(http.MethodGet, "/v1", nil)
	w := httptest.NewRecorder()

	s.listSupportedFunctions(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var result listSupportedFunctionsResponse
	err := json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, functionalGroupCode, result[0].FuncGroupCode)
	require.NotEmpty(t, result[0].Kinds)
	require.NotEmpty(t, result[0].Endpoints)
}

func TestServer_listSupportedFunctions_WrongMethod(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	req := httptest.NewRequest(http.MethodPost, "/v1", nil)
	w := httptest.NewRecorder()

	s.listSupportedFunctions(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestServer_listAttributeDefinitions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSv := mock.NewMockSupervisorContract(ctrl)
	s := setupTestServerWithSupervisor(t, mockSv)

	testConfig := model.Scan{
		Version: 0,
		Filesystem: model.Filesystem{
			Enabled: true,
			Paths:   []string{"/test"},
		},
	}

	mockSv.EXPECT().JobConfiguration(gomock.Any(), s.jobName).Return(testConfig, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/discoveryProvider/test-kind/attributes", nil)
	w := httptest.NewRecorder()

	s.listAttributeDefinitions(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var result listAttributeDefinitionsResponse
	err := json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, lensConfigurationAttrUUID, result[0].UUID)
	require.Equal(t, lensConfigurationAttrName, result[0].Name)
	require.Equal(t, 1, len(result[0].Content))
	require.Equal(t, "yaml", result[0].Content[0].Data.Language)
	require.Equal(t, "dmVyc2lvbjogMApmaWxlc3lzdGVtOgogICAgZW5hYmxlZDogdHJ1ZQogICAgcGF0aHM6CiAgICAgICAgLSAvdGVzdApjb250YWluZXJzOgogICAgZW5hYmxlZDogZmFsc2UKICAgIGNvbmZpZzogW10KcG9ydHM6CiAgICBlbmFibGVkOiBmYWxzZQogICAgYmluYXJ5OiAiIgogICAgcG9ydHM6ICIiCiAgICBpcHY0OiBmYWxzZQogICAgaXB2NjogZmFsc2UKc2VydmljZToKICAgIHZlcmJvc2U6IGZhbHNlCiAgICBsb2c6ICIiCg==", result[0].Content[0].Data.Code)
}

func TestServer_listAttributeDefinitions_ConfigError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSv := mock.NewMockSupervisorContract(ctrl)
	s := setupTestServerWithSupervisor(t, mockSv)

	mockSv.EXPECT().JobConfiguration(gomock.Any(), s.jobName).Return(model.Scan{}, fmt.Errorf("config error"))

	req := httptest.NewRequest(http.MethodGet, "/v1/discoveryProvider/test-kind/attributes", nil)
	w := httptest.NewRecorder()

	s.listAttributeDefinitions(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestServer_validateAttributes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	testConfig := model.Scan{
		Version: 0,
		Filesystem: model.Filesystem{
			Enabled: true,
		},
	}

	yamlData, err := yaml.Marshal(testConfig)
	require.NoError(t, err)

	attrs := []attrCodeblock{
		{
			UUID:        lensConfigurationAttrUUID,
			Name:        lensConfigurationAttrName,
			ContentType: ptrString(lensConfigurationAttrContentType),
			Content: []attrCodeblockContent{
				{
					Data: attrCodeblockContentData{
						Language: "yaml",
						Code:     base64.StdEncoding.EncodeToString(yamlData),
					},
				},
			},
		},
	}

	body, err := json.Marshal(attrs)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/test-kind/attributes/validate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.validateAttributes(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestServer_validateAttributes_InvalidJSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/test-kind/attributes/validate", strings.NewReader("invalid json"))
	w := httptest.NewRecorder()

	s.validateAttributes(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestServer_validateAttributes_ValidationError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	attrs := []attrCodeblock{
		{
			UUID: "unknown-uuid",
			Name: "unknown",
		},
	}

	body, err := json.Marshal(attrs)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/test-kind/attributes/validate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.validateAttributes(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
}

func TestServer_discoverCertificate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSv := mock.NewMockSupervisorContract(ctrl)
	s := setupTestServerWithSupervisor(t, mockSv)

	mockSv.EXPECT().Start(s.jobName)

	reqBody := discoverCertificateRequest{
		Name:       "test-discovery",
		Kind:       s.kind,
		Attributes: []attrCodeblock{},
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/discover", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.discoverCertificate(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result discoverCertificateResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)
	require.NotEmpty(t, result.UUID)
	require.Equal(t, "inProgress", result.Status)
}

func TestServer_discoverCertificate_WithAttributes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSv := mock.NewMockSupervisorContract(ctrl)
	s := setupTestServerWithSupervisor(t, mockSv)

	testConfig := model.Scan{
		Version: 0,
		Filesystem: model.Filesystem{
			Enabled: true,
		},
	}

	yamlData, err := yaml.Marshal(testConfig)
	require.NoError(t, err)

	mockSv.EXPECT().ConfigureJob(gomock.Any(), s.jobName, gomock.Any())
	mockSv.EXPECT().Start(s.jobName)

	reqBody := discoverCertificateRequest{
		Name: "test-discovery",
		Kind: s.kind,
		Attributes: []attrCodeblock{
			{
				UUID:        lensConfigurationAttrUUID,
				Name:        lensConfigurationAttrName,
				ContentType: ptrString(lensConfigurationAttrContentType),
				Content: []attrCodeblockContent{
					{
						Data: attrCodeblockContentData{
							Language: "yaml",
							Code:     base64.StdEncoding.EncodeToString(yamlData),
						},
					},
				},
			},
		},
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/discover", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.discoverCertificate(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestServer_discoverCertificate_InvalidJSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/discover", strings.NewReader("invalid json"))
	w := httptest.NewRecorder()

	s.discoverCertificate(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestServer_discoverCertificate_EmptyContent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	reqBody := discoverCertificateRequest{
		Name: "test-discovery",
		Kind: s.kind,
		Attributes: []attrCodeblock{
			{
				UUID:    lensConfigurationAttrUUID,
				Content: []attrCodeblockContent{},
			},
		},
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/discover", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.discoverCertificate(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestServer_discoverCertificate_InvalidBase64(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	reqBody := discoverCertificateRequest{
		Name: "test-discovery",
		Kind: s.kind,
		Attributes: []attrCodeblock{
			{
				UUID: lensConfigurationAttrUUID,
				Content: []attrCodeblockContent{
					{
						Data: attrCodeblockContentData{
							Code: "invalid-base64!!!",
						},
					},
				},
			},
		},
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/discover", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.discoverCertificate(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestServer_discoverCertificate_InvalidYAML(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	reqBody := discoverCertificateRequest{
		Name: "test-discovery",
		Kind: s.kind,
		Attributes: []attrCodeblock{
			{
				UUID: lensConfigurationAttrUUID,
				Content: []attrCodeblockContent{
					{
						Data: attrCodeblockContentData{
							Code: base64.StdEncoding.EncodeToString([]byte("invalid: yaml: content:")),
						},
					},
				},
			},
		},
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/discover", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.discoverCertificate(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestServer_discoverCertificate_AlreadyInProgress(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSv := mock.NewMockSupervisorContract(ctrl)
	s := setupTestServerWithSupervisor(t, mockSv)

	mockSv.EXPECT().Start(s.jobName)

	reqBody := discoverCertificateRequest{
		Name:       "test-discovery",
		Kind:       s.kind,
		Attributes: []attrCodeblock{},
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	// First request
	req1 := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/discover", bytes.NewReader(body))
	w1 := httptest.NewRecorder()
	s.discoverCertificate(w1, req1)
	require.Equal(t, http.StatusOK, w1.Result().StatusCode)

	// Second request while first is in progress
	req2 := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/discover", bytes.NewReader(body))
	w2 := httptest.NewRecorder()
	s.discoverCertificate(w2, req2)
	require.Equal(t, http.StatusBadRequest, w2.Result().StatusCode)
}

func TestServer_getDiscovery(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	// Start a discovery
	uuid := "test-uuid-123"
	err := store.Start(context.Background(), s.db, uuid)
	require.NoError(t, err)

	reqBody := getDiscoveryRequest{
		Name:         "test-discovery",
		Kind:         s.kind,
		PageNumber:   1,
		ItemsPerPage: 10,
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/discover/"+uuid, bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"uuid": uuid})
	w := httptest.NewRecorder()

	s.getDiscovery(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result getDiscoveryResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)
	require.Equal(t, uuid, result.UUID)
	require.Equal(t, "inProgress", result.Status)
}

func TestServer_getDiscovery_Completed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	uuid := "test-uuid-456"
	err := store.Start(context.Background(), s.db, uuid)
	require.NoError(t, err)

	uploadKey := `{"serialNumber":"urn:uuid:9a74ce22-21aa-4f8e-b7ff-d4783cd425d8","version":1,"stats":{"crypto-stats":{"crypto-assets":{"total":1,"algorithms":{"total":1},"certificates":{"total":0},"protocols":{"total":0},"related-crypto-materials":{"total":0}}}}}`
	err = store.FinishOK(context.Background(), s.db, uuid, uploadKey)
	require.NoError(t, err)

	reqBody := getDiscoveryRequest{
		Name:         "test-discovery",
		Kind:         s.kind,
		PageNumber:   1,
		ItemsPerPage: 10,
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/discover/"+uuid, bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"uuid": uuid})
	w := httptest.NewRecorder()

	s.getDiscovery(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result getDiscoveryResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)
	require.Equal(t, uuid, result.UUID)
	require.Equal(t, "completed", result.Status)
	require.Len(t, result.Meta, 2)
	require.Equal(t, lensResultMetadataUploadKeyAttrUUID, result.Meta[0].UUID)
	require.Equal(t, lensResultMetadataURIAttrUUID, result.Meta[1].UUID)
}

func TestServer_getDiscovery_Failed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	uuid := "test-uuid-789"
	err := store.Start(context.Background(), s.db, uuid)
	require.NoError(t, err)

	failureReason := "test failure reason"
	err = store.FinishErr(context.Background(), s.db, uuid, failureReason)
	require.NoError(t, err)

	reqBody := getDiscoveryRequest{
		Name:         "test-discovery",
		Kind:         s.kind,
		PageNumber:   1,
		ItemsPerPage: 10,
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/discover/"+uuid, bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"uuid": uuid})
	w := httptest.NewRecorder()

	s.getDiscovery(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result getDiscoveryResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)
	require.Equal(t, uuid, result.UUID)
	require.Equal(t, "failed", result.Status)
	require.Len(t, result.Meta, 1)
	require.Equal(t, lensResultMetadataFailureReasonAttrUUID, result.Meta[0].UUID)
}

func TestServer_getDiscovery_MissingUUID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	reqBody := getDiscoveryRequest{
		Name: "test-discovery",
		Kind: s.kind,
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/discover/", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.getDiscovery(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestServer_getDiscovery_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	uuid := "non-existent-uuid"
	reqBody := getDiscoveryRequest{
		Name:         "test-discovery",
		Kind:         s.kind,
		PageNumber:   1,
		ItemsPerPage: 10,
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/discover/"+uuid, bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"uuid": uuid})
	w := httptest.NewRecorder()

	s.getDiscovery(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestServer_getDiscovery_WrongKind(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	uuid := "test-uuid-wrongkind"
	err := store.Start(context.Background(), s.db, uuid)
	require.NoError(t, err)

	reqBody := getDiscoveryRequest{
		Name:         "test-discovery",
		Kind:         "wrong-kind",
		PageNumber:   1,
		ItemsPerPage: 10,
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/discover/"+uuid, bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"uuid": uuid})
	w := httptest.NewRecorder()

	s.getDiscovery(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestServer_getDiscovery_InvalidJSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	uuid := "test-uuid"
	req := httptest.NewRequest(http.MethodPost, "/v1/discoveryProvider/discover/"+uuid, strings.NewReader("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"uuid": uuid})
	w := httptest.NewRecorder()

	s.getDiscovery(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestServer_deleteDiscovery(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	uuid := "test-uuid-delete"
	err := store.Start(context.Background(), s.db, uuid)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/v1/discoveryProvider/discover/"+uuid, nil)
	req = mux.SetURLVars(req, map[string]string{"uuid": uuid})
	w := httptest.NewRecorder()

	s.deleteDiscovery(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestServer_deleteDiscovery_MissingUUID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	req := httptest.NewRequest(http.MethodDelete, "/v1/discoveryProvider/discover/", nil)
	w := httptest.NewRecorder()

	s.deleteDiscovery(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestServer_deleteDiscovery_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := setupTestServer(t, ctrl)

	uuid := "non-existent-uuid"
	req := httptest.NewRequest(http.MethodDelete, "/v1/discoveryProvider/discover/"+uuid, nil)
	req = mux.SetURLVars(req, map[string]string{"uuid": uuid})
	w := httptest.NewRecorder()

	s.deleteDiscovery(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestToJson(t *testing.T) {
	w := httptest.NewRecorder()
	ctx := context.Background()

	resp := checkHealthResponse{Status: "ok"}
	toJson(ctx, w, resp)

	result := w.Result()
	require.Equal(t, http.StatusOK, result.StatusCode)
	require.Equal(t, "application/json", result.Header.Get("Content-Type"))

	body, err := io.ReadAll(result.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "ok")
}

func TestToJsonErr(t *testing.T) {
	w := httptest.NewRecorder()
	ctx := context.Background()

	resp := generalErrMsgResp{Message: "error message"}
	toJsonErr(ctx, w, resp, http.StatusBadRequest)

	result := w.Result()
	require.Equal(t, http.StatusBadRequest, result.StatusCode)
	require.Equal(t, "application/json", result.Header.Get("Content-Type"))

	body, err := io.ReadAll(result.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "error message")
}

// Helper functions

func setupTestServer(t *testing.T, ctrl *gomock.Controller) *Server {
	mockSv := mock.NewMockSupervisorContract(ctrl)
	return setupTestServerWithSupervisor(t, mockSv)
}

func setupTestServerWithSupervisor(t *testing.T, mockSv *mock.MockSupervisorContract) *Server {
	lensURL, err := url.Parse("http://localhost:8080")
	require.NoError(t, err)

	coreURL, err := url.Parse("http://localhost:8081")
	require.NoError(t, err)

	repoURL, err := url.Parse("http://localhost:8082")
	require.NoError(t, err)

	cfg := model.Service{
		ServiceFields: model.ServiceFields{
			Verbose: false,
			Log:     "discard",
		},
		Mode: model.ServiceModeDiscovery,
		Dir:  "/tmp",
		Repository: &model.Repository{
			URL: model.URL{URL: repoURL},
		},
		Server: &model.LensServer{
			BaseURL:   model.URL{URL: lensURL},
			StateFile: ":memory:",
		},
		Core: &model.Core{
			BaseURL: model.URL{URL: coreURL},
		},
	}

	s, err := New(context.Background(), cfg, mockSv, "test-job")
	require.NoError(t, err)

	return s
}
