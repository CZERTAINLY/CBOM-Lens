package dscvr

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/CZERTAINLY/CBOM-lens/internal/dscvr/store"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	uuidpkg "github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.yaml.in/yaml/v4"
)

const (
	repositoryUploadPath = "api/v1/bom"
)

func (s *Server) getDiscovery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	uuid := vars["uuid"]

	if uuid == "" {
		toJsonErr(ctx, w, generalErrMsgResp{Message: "Missing uuid variable."}, http.StatusBadRequest)
		return
	}
	slog.DebugContext(ctx, "Parsed uuid.", slog.String("uuid", uuid))

	b, err := io.ReadAll(r.Body)
	if err != nil {
		slog.ErrorContext(ctx, "Calling `io.ReadAll()` failed", slog.String("error", err.Error()))
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}
	slog.DebugContext(ctx, "Request body.", slog.String("body", string(b)))

	var request getDiscoveryRequest
	if err := json.Unmarshal(b, &request); err != nil {
		slog.DebugContext(ctx, "Calling `json.Unmarshal()` failed", slog.String("error", err.Error()))
		toJsonErr(ctx, w, generalErrMsgResp{Message: fmt.Sprintf("Failed to unmarshal request: %s", err)}, http.StatusBadRequest)
		return
	}

	if request.Kind != s.kind {
		slog.DebugContext(ctx, "Request has wrong kind.", slog.String("expected", s.kind), slog.String("got", request.Kind))
		toJsonErr(ctx, w, generalErrMsgResp{Message: fmt.Sprintf("Wrong kind, expected: %q, got: %q", s.kind, request.Kind)}, http.StatusBadRequest)
		return
	}

	dr, err := store.Get(ctx, s.db, uuid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		slog.DebugContext(ctx, "UUID not found", slog.String("uuid", uuid))
		toJsonErr(ctx, w, generalErrMsgResp{Message: fmt.Sprintf("UUID %q not found.", uuid)}, http.StatusNotFound)
		return
	case err != nil:
		slog.ErrorContext(ctx, "Calling `store.Get()` failed", slog.String("error", err.Error()))
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	var status string
	switch dr.InProgress {
	case true:
		status = "inProgress"
		toJson(ctx, w, getDiscoveryResponse{
			UUID:            uuid,
			Name:            request.Name,
			Status:          status,
			CertificateData: []any{},
			Meta:            []getDiscoveryMetaItem{},
		})
		return

	case false:
		// sanity assertion
		if dr.Success == nil {
			slog.ErrorContext(ctx, "On DiscoveryRow, InProgress == false, but *Success == nil", slog.String("discovery-row", dr.String()))
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}

		var mp metaProperties
		var mis []getDiscoveryMetaItem
		if *dr.Success {
			status = "completed"

			mis = append(mis, getDiscoveryMetaItem{
				Version:     2,
				UUID:        lensResultMetadataUploadKeyAttrUUID,
				Name:        lensResultMetadataUploadKeyAttrName,
				Type:        "meta",
				ContentType: "codeblock",
				Properties: metaProperties{
					Label:   "Uploaded CBOM-Repository Key and Simple Crypto Statistics",
					Visible: true,
				},
				Content: []any{
					metaItemContentCodeblock{
						Data: metaItemContentCodeblockItem{
							Language: "json",
							Code:     base64.StdEncoding.EncodeToString([]byte(*dr.UploadKey)),
						},
					},
				},
			})

			type repositoryRespKeys struct {
				SerialNumber string `json:"serialNumber"`
				Version      int    `json:"version"`
			}
			var rrk repositoryRespKeys
			if err := json.Unmarshal([]byte(*dr.UploadKey), &rrk); err != nil {
				slog.ErrorContext(ctx, "`json.Unmarshal()` failed", slog.String("error", err.Error()))
				http.Error(w, "Internal server error.", http.StatusInternalServerError)
				return
			}

			mis = append(mis, getDiscoveryMetaItem{
				Version:     2,
				UUID:        lensResultMetadataURIAttrUUID,
				Name:        lensResultMetadataURIAttrName,
				Type:        "meta",
				ContentType: "string",
				Properties: metaProperties{
					Label:   "Uploaded CBOM-Repository URI",
					Visible: true,
				},
				Content: []any{
					metaItemContentString{
						Data: fmt.Sprintf("%s/%s/%s?version=%d", s.cfg.Repository.URL.String(), repositoryUploadPath, rrk.SerialNumber, rrk.Version),
					},
				},
			})

		} else {
			status = "failed"
			mp = metaProperties{
				Label:   "Failure reason",
				Visible: true,
			}
			mis = append(mis, getDiscoveryMetaItem{
				Version:     2,
				UUID:        lensResultMetadataFailureReasonAttrUUID,
				Name:        lensResultMetadataFailureReasonAttrName,
				Type:        "meta",
				ContentType: "string",
				Properties:  mp,
				Content: []any{
					metaItemContentString{
						Data: *dr.FailureReason,
					},
				},
			})
		}

		toJson(ctx, w, getDiscoveryResponse{
			UUID:            uuid,
			Name:            request.Name,
			Status:          status,
			CertificateData: []any{},
			Meta:            mis,
		})
		return
	}
}

func (s *Server) discoverCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		slog.ErrorContext(ctx, "Calling `io.ReadAll()` failed", slog.String("error", err.Error()))
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}
	slog.DebugContext(ctx, "Request body.", slog.String("body", string(b)))

	var req discoverCertificateRequest
	if err := json.Unmarshal(b, &req); err != nil {
		slog.DebugContext(ctx, "Calling `json.Unmarshal()` failed", slog.String("error", err.Error()))
		toJsonErr(r.Context(), w, generalErrMsgResp{Message: fmt.Sprintf("Failed to unmarshal request: %s", err)}, http.StatusBadRequest)
		return
	}

	var newConf model.Scan
	doConf := false

	if len(req.Attributes) > 0 {
		doConf = true
		if len(req.Attributes[0].Content) == 0 {
			slog.DebugContext(ctx, "Decoding attribute failed - Content array has zero length.")
			toJsonErr(r.Context(), w, generalErrMsgResp{Message: "Decoding attribute failed."}, http.StatusBadRequest)
			return
		}

		data, ok := req.Attributes[0].Content[0].Data.(attrCodeblockContentData)
		if !ok {
			toJsonErr(r.Context(), w, generalErrMsgResp{Message: "Decoding attribute data failed: not expected type."}, http.StatusBadRequest)
			return
		}

		decodedAttr, err := base64.StdEncoding.DecodeString(data.Code)
		if err != nil {
			slog.DebugContext(ctx, "Decoding attribute failed.", slog.String("error", err.Error()))
			toJsonErr(r.Context(), w, generalErrMsgResp{Message: "Decoding attribute failed."}, http.StatusBadRequest)
			return
		}
		slog.DebugContext(ctx, "Scan configuration decoded from attribute", slog.String("scan-config", string(decodedAttr)))

		if err := yaml.Unmarshal(decodedAttr, &newConf); err != nil {
			slog.DebugContext(ctx, "Calling `yaml.Unmarshal()` failed", slog.String("error", err.Error()))
			toJsonErr(r.Context(), w, generalErrMsgResp{Message: "Decoding attribute failed."}, http.StatusBadRequest)
			return
		}
	}

	uuid := uuidpkg.New().String()
	ok, err := s.startIf(ctx, uuid)
	if err != nil {
		slog.ErrorContext(ctx, "Calling `dscvrServer.startIf()` failed", slog.String("error", err.Error()), slog.String("uuid", uuid))
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}
	if !ok {
		toJsonErr(r.Context(), w, "Previous discovery still in progress.", http.StatusBadRequest)
		return
	}

	if doConf {
		s.sv.ConfigureJob(ctx, s.jobName, newConf)
	}
	s.sv.Start(s.jobName)

	toJson(r.Context(), w, discoverCertificateResponse{
		UUID:            uuid,
		Name:            "CBOM-Lens Scan",
		Status:          "inProgress",
		CertificateData: []any{},
		Meta:            []any{},
	})
}

func (s *Server) deleteDiscovery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	uuid := vars["uuid"]

	if uuid == "" {
		toJsonErr(r.Context(), w, generalErrMsgResp{Message: "Missing uuid variable."}, http.StatusBadRequest)
		return
	}
	slog.DebugContext(ctx, "Parsed uuid.", slog.String("uuid", uuid))

	err := store.Delete(ctx, s.db, uuid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		toJsonErr(r.Context(), w, generalErrMsgResp{Message: fmt.Sprintf("UUID %q not found.", uuid)}, http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) validateAttributes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	b, err := io.ReadAll(r.Body)
	if err != nil {
		slog.ErrorContext(ctx, "Calling `io.ReadAll()` failed.", slog.String("error", err.Error()))
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}
	slog.DebugContext(ctx, "Request body.", slog.String("body", string(b)))

	var attrs []attrCodeblock
	if err := json.Unmarshal(b, &attrs); err != nil {
		slog.DebugContext(ctx, "Calling `json.Unmarshal()` failed", slog.String("error", err.Error()))
		toJsonErr(r.Context(), w, generalErrMsgResp{Message: "Request body contains invalid JSON."}, http.StatusUnprocessableEntity)
		return
	}
	type validationErrResp []string
	if err := validateAttr(attrs); err != nil {
		slog.DebugContext(ctx, "Validating attribute failed.", slog.String("error", err.Error()))
		toJsonErr(r.Context(), w, validationErrResp{err.Error()}, http.StatusUnprocessableEntity)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) listAttributeDefinitions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	currentConfig, err := s.sv.JobConfiguration(r.Context(), s.jobName)
	if err != nil {
		slog.WarnContext(r.Context(),
			"Getting configuration for a job that was supposed to exist failed. Using a default configuration example.",
			slog.String("job-name", s.jobName))
		currentConfig = model.Scan{}
	}

	b, err := yaml.Marshal(&currentConfig)
	if err != nil {
		slog.ErrorContext(ctx, "Calling `json.Marshal()` failed", slog.String("error", err.Error()))
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}

	info := attrCodeblock{
		Version:     ptrInt(2),
		UUID:        lensConfigurationInfoAttrUUID,
		Name:        lensConfigurationInfoAttrName,
		Description: ptrString("Describe configuration options for scanning."),
		Type:        ptrString(lensConfigurationInfoAttrType),
		ContentType: ptrString(lensConfigurationInfoAttrContentType),
		Properties: &attrProperties{
			Label:   "CBOM-Lens scan configuration.",
			Visible: true,
		},
		Content: []attrCodeblockContent{
			{
				Data: lensConfigurationInfoData,
			},
		},
	}

	config := attrCodeblock{
		Version:     ptrInt(2),
		UUID:        lensConfigurationAttrUUID,
		Name:        lensConfigurationAttrName,
		Description: ptrString("Configuration options for scanning."),
		Type:        ptrString(lensConfigurationAttrType),
		ContentType: ptrString(lensConfigurationAttrContentType),
		Properties: &attrProperties{
			Label:   "CBOM-Lens scan configuration options.",
			Visible: true,
		},
		Content: []attrCodeblockContent{
			{
				Data: attrCodeblockContentData{
					Language: "yaml",
					Code:     base64.StdEncoding.EncodeToString(b),
				},
			},
		},
	}
	var resp = listAttributeDefinitionsResponse{info, config}

	toJson(r.Context(), w, resp)
}

func (s *Server) listSupportedFunctions(w http.ResponseWriter, r *http.Request) {
	// Assert http GET
	if r.Method != http.MethodGet {
		http.Error(w, "Allowed methods: [ GET ].", http.StatusMethodNotAllowed)
		return
	}

	item := supportedFunction{
		FuncGroupCode: s.funcGroupCode,
		Kinds:         []string{s.kind},
	}

	endpoints := DiscoveryProviderEndpoints()
	for name, def := range endpoints {
		item.Endpoints = append(item.Endpoints, supportedFunctionEndpoint{
			Name:     name,
			Context:  strings.Replace(def.Path, "{functionalGroup}", s.funcGroupCode, 1),
			Method:   def.Method,
			Required: false,
		})
	}

	toJson(r.Context(), w, listSupportedFunctionsResponse{item})
}

func (s *Server) checkHealth(w http.ResponseWriter, r *http.Request) {
	// Assert http GET
	if r.Method != http.MethodGet {
		http.Error(w, "Allowed methods: [ GET ].", http.StatusMethodNotAllowed)
		return
	}

	toJson(r.Context(), w, checkHealthResponse{
		Status: "ok",
	})
}

func toJson(ctx context.Context, w http.ResponseWriter, resp any) {
	b, err := json.Marshal(resp)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to marshal structure to json.", slog.String("error", err.Error()))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal server error."))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}
func toJsonErr(ctx context.Context, w http.ResponseWriter, resp any, statusCode int) {
	b, err := json.Marshal(resp)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to marshal structure to json.", slog.String("error", err.Error()))
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal server error."))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(b)
}
