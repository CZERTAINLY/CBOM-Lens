package dscvr

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/dscvr/store"
	"github.com/CZERTAINLY/CBOM-lens/internal/log"
	"github.com/CZERTAINLY/CBOM-lens/internal/model"

	"github.com/gorilla/mux"
)

const defaultCallbackStoreTimeout = 10 * time.Second

//go:generate mockgen -destination=./mock/supervisor.go -package=mock github.com/CZERTAINLY/CBOM-lens/internal/dscvr SupervisorContract
type SupervisorContract interface {
	ConfigureJob(ctx context.Context, name string, cfg model.Scan)
	JobConfiguration(ctx context.Context, name string) (model.Scan, error)
	Start(name string)
}

type Server struct {
	cfg model.Service
	sv  SupervisorContract

	kind          string
	funcGroupCode string
	jobName       string
	db            *sql.DB

	mx          sync.Mutex
	runningFlag bool
	uuid        string
}

func New(ctx context.Context, cfg model.Service, sv SupervisorContract, jobName string) (*Server, error) {
	// config assertions
	switch {
	case cfg.Mode != model.ServiceModeDiscovery:
		return nil, fmt.Errorf(
			"mode %q not compatible with CZERTAINLY Core integration, please provide correct configuration using %q mode",
			cfg.Mode, model.ServiceModeDiscovery)

	case cfg.Repository == nil:
		return nil, fmt.Errorf("configuration section 'repository' is required with mode %q", model.ServiceModeDiscovery)

	case cfg.Server == nil:
		return nil, fmt.Errorf("configuration section 'server' is required with mode %q", model.ServiceModeDiscovery)

	case cfg.Core == nil:
		return nil, fmt.Errorf("configuration section 'core' is required with mode %q", model.ServiceModeDiscovery)
	}

	cfg.Server.BaseURL.Path = strings.TrimSuffix(cfg.Server.BaseURL.Path, "/")
	cfg.Core.BaseURL.Path = strings.TrimSuffix(cfg.Core.BaseURL.Path, "/")
	cfg.Repository.URL.Path = strings.TrimRight(cfg.Repository.URL.Path, "/")

	var kind string
	if cfg.Server.BaseURL.Port() == "" {
		kind = fmt.Sprintf("%s-%s", cfg.Server.BaseURL.Hostname(), "default")
	} else {
		kind = fmt.Sprintf("%s-%s", cfg.Server.BaseURL.Hostname(), cfg.Server.BaseURL.Port())
	}

	// init new or read-in the existing sqlite state file
	db, err := store.InitDB(ctx, cfg.Server.StateFile)
	if err != nil {
		return nil, fmt.Errorf("failure initializing sqlite database: %w", err)
	}

	return &Server{
		cfg:           cfg,
		sv:            sv,
		kind:          kind,
		funcGroupCode: functionalGroupCode,
		jobName:       jobName,
		db:            db,
	}, nil
}

// when there is no discovery in progress, startIf stores 'dscvrUUID`,
// sets the running flag and returns true,
// false otherwise
func (s *Server) startIf(ctx context.Context, dscvrUUID string) (bool, error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	if s.runningFlag {
		return false, nil
	}

	s.runningFlag = true
	s.uuid = dscvrUUID

	if err := store.Start(ctx, s.db, s.uuid); err != nil {
		s.runningFlag = false
		s.uuid = ""
		return false, err
	}

	return true, nil
}

func (s *Server) UploadedCallback(err error, jobName, resp string) {
	if jobName != s.jobName {
		return
	}

	s.mx.Lock()
	defer s.mx.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), defaultCallbackStoreTimeout)
	defer cancel()

	if err == nil {
		if err := store.FinishOK(ctx, s.db, s.uuid, base64.StdEncoding.EncodeToString([]byte(resp))); err != nil {
			slog.Error("`store.FinishOK()` failed", slog.String("error", err.Error()))
		}
	} else {
		if err := store.FinishErr(ctx, s.db, s.uuid, err.Error()); err != nil {
			slog.Error("`store.FinishErr()` failed", slog.String("error", err.Error()))
		}
	}

	s.runningFlag = false
	s.uuid = ""
}

func (s *Server) Close(ctx context.Context) {
	if err := s.db.Close(); err != nil {
		slog.ErrorContext(ctx, "Got error while closing *sql.DB.", slog.String("error", err.Error()))
	}
}

// func (s *Server) Handler() *http.ServeMux {
func (s *Server) Handler() *mux.Router {

	r := mux.NewRouter()

	r.Use(httpInfoContext)

	for k, v := range DiscoveryProviderEndpoints() {
		var handler func(http.ResponseWriter, *http.Request)
		switch k {
		case "checkHealth":
			handler = s.checkHealth
		case "listSupportedFunctions":
			handler = s.listSupportedFunctions
		case "listAttributeDefinitions":
			handler = s.listAttributeDefinitions
		case "validateAttributes":
			handler = s.validateAttributes
		case "deleteDiscovery":
			handler = s.deleteDiscovery
		case "discoverCertificate":
			handler = s.discoverCertificate
		case "getDiscovery":
			handler = s.getDiscovery

		default:
			// safeguard against Core protocol changes not being mapped here
			// since this is a programmer's mistake, panic is deliberate
			panic("function 'DiscoveryProviderEndpoints' was extended, but route was not added to Handler() in `internal/dscvr/server.go`")
		}

		path := strings.Replace(v.Path, "{functionalGroup}", s.funcGroupCode, 1)
		path = strings.Replace(path, "{kind}", s.kind, 1)

		r.HandleFunc(fmt.Sprintf("%s%s", s.cfg.Server.BaseURL.Path, path), handler).Methods(v.Method)
	}

	return r
}

func httpInfoContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Add structured HTTP attributes to context
		ctx := log.ContextAttrs(r.Context(), slog.Group("http-info",
			slog.String("method", r.Method),
			slog.String("url-path", r.URL.Path),
		))

		// Pass updated request into chain
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) RegisterConnector(ctx context.Context) error {
	endpoint := DiscoveryRegisterEndpoint()

	reqUrl := fmt.Sprintf("%s%s", s.cfg.Core.BaseURL, endpoint.Path)
	reqBody := registerConnectorRequest{
		Name:     fmt.Sprintf("cbom-lens-%s", s.cfg.Server.BaseURL),
		Url:      s.cfg.Server.BaseURL.String(),
		AuthType: "none",
	}

	b, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	slog.DebugContext(ctx, "Registering czertainly core connector.",
		slog.String("request-url", reqUrl), slog.String("request-body", string(b)))

	req, err := http.NewRequestWithContext(ctx, endpoint.Method, reqUrl, bytes.NewReader(b))
	if err != nil {
		return err
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Content-Type", "application/json")

	ctx = log.ContextAttrs(ctx, slog.Group("http-request",
		slog.String("method", endpoint.Method),
		slog.String("url", reqUrl),
		slog.String("body", string(b)),
	))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "Http request failed while registering czertainly core connector.", slog.String("error", err.Error()))
		return errors.New("registering czertainly core connector failed")
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if err := decodeRegisterResponse(ctx, resp); err != nil {
		return fmt.Errorf("registering czertainly core connector failed: %w", err)
	}

	return nil
}

func decodeRegisterResponse(ctx context.Context, resp *http.Response) error {
	// Note: When registering an already previously registered connector, the czertainly core
	// will return message with a text similar to:
	//	`["Connector(s) with same kinds already exists:<name-of-kind>"]`

	switch resp.StatusCode {
	case http.StatusOK:
		slog.Debug("Czertainly core connector successfully registered.")
		return nil
	case http.StatusBadRequest:
		fallthrough
	case http.StatusNotFound:
		if resp.Header.Get("Content-Type") == "application/json" {
			type registerResp struct {
				Message string `json:"message"`
			}
			var rr registerResp
			if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
				slog.ErrorContext(ctx, "Decoding response json failed.", slog.String("error", err.Error()))
				return fmt.Errorf("status code %d", resp.StatusCode)
			}
			if strings.Contains(rr.Message, "already exists") {
				slog.Debug("Czertainly core connector already registered.")
				return nil
			}

			return fmt.Errorf("status code: %d, message: %s", resp.StatusCode, rr.Message)
		}
		return fmt.Errorf("status code %d", resp.StatusCode)

	case http.StatusUnprocessableEntity:
		if resp.Header.Get("Content-Type") == "application/json" {
			type registerResp []string
			var rr registerResp
			if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
				slog.ErrorContext(ctx, "Decoding response json failed.", slog.String("error", err.Error()))
				return fmt.Errorf("status code %d", resp.StatusCode)
			}
			var sb strings.Builder
			for _, cpy := range rr {
				if strings.Contains(cpy, "already exists") {
					slog.Debug("Czertainly core connector already registered.")
					return nil
				}
				sb.WriteString(fmt.Sprintf("%s ", cpy))
			}
			return fmt.Errorf("status code: %d, message: %s", resp.StatusCode, sb.String())
		}
		return fmt.Errorf("status code %d", resp.StatusCode)

	default:
		return fmt.Errorf("unexpected status code returned: %d", resp.StatusCode)
	}
}
