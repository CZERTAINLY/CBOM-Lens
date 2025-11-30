package dscvr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CZERTAINLY/Seeker/internal/dscvr/store"
	"github.com/CZERTAINLY/Seeker/internal/model"
	"github.com/CZERTAINLY/Seeker/internal/service"

	_ "modernc.org/sqlite"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		cfg         model.Service
		setupSv     bool
		jobName     string
		wantErr     bool
		errContains string
	}{
		{
			name: "valid configuration",
			cfg: model.Service{
				Mode: model.ServiceModeDiscovery,
				Repository: &model.Repository{
					URL: mustParseURL(t, "http://example.com"),
				},
				Seeker: &model.SeekerServer{
					Addr:      model.TCPAddr{},
					BaseURL:   mustParseURL(t, "http://localhost:8080/api"),
					StateFile: ":memory:",
				},
				Core: &model.Core{
					BaseURL: mustParseURL(t, "http://core.example.com/api"),
				},
			},
			setupSv: true,
			jobName: "test-job",
			wantErr: false,
		},
		{
			name: "invalid mode",
			cfg: model.Service{
				Mode: model.ServiceModeManual,
			},
			setupSv:     true,
			jobName:     "test-job",
			wantErr:     true,
			errContains: "not compatible with CZERTAINLY Core integration",
		},
		{
			name: "missing repository",
			cfg: model.Service{
				Mode:       model.ServiceModeDiscovery,
				Repository: nil,
			},
			setupSv:     true,
			jobName:     "test-job",
			wantErr:     true,
			errContains: "configuration section 'repository' is required",
		},
		{
			name: "missing seeker",
			cfg: model.Service{
				Mode: model.ServiceModeDiscovery,
				Repository: &model.Repository{
					URL: mustParseURL(t, "http://example.com"),
				},
				Seeker: nil,
			},
			setupSv:     true,
			jobName:     "test-job",
			wantErr:     true,
			errContains: "configuration section 'seeker' is required",
		},
		{
			name: "missing core",
			cfg: model.Service{
				Mode: model.ServiceModeDiscovery,
				Repository: &model.Repository{
					URL: mustParseURL(t, "http://example.com"),
				},
				Seeker: &model.SeekerServer{
					BaseURL:   mustParseURL(t, "http://localhost:8080"),
					StateFile: ":memory:",
				},
				Core: nil,
			},
			setupSv:     true,
			jobName:     "test-job",
			wantErr:     true,
			errContains: "configuration section 'core' is required",
		},
		{
			name: "trims trailing slashes from paths",
			cfg: model.Service{
				Mode: model.ServiceModeDiscovery,
				Repository: &model.Repository{
					URL: mustParseURL(t, "http://example.com"),
				},
				Seeker: &model.SeekerServer{
					BaseURL:   mustParseURL(t, "http://localhost:8080/api/"),
					StateFile: ":memory:",
				},
				Core: &model.Core{
					BaseURL: mustParseURL(t, "http://core.example.com/api/"),
				},
			},
			setupSv: true,
			jobName: "test-job",
			wantErr: false,
		},
		{
			name: "handles URL without port",
			cfg: model.Service{
				Mode: model.ServiceModeDiscovery,
				Repository: &model.Repository{
					URL: mustParseURL(t, "http://example.com"),
				},
				Seeker: &model.SeekerServer{
					BaseURL:   mustParseURL(t, "http://localhost"),
					StateFile: ":memory:",
				},
				Core: &model.Core{
					BaseURL: mustParseURL(t, "http://core.example.com"),
				},
			},
			setupSv: true,
			jobName: "test-job",
			wantErr: false,
		},
		{
			name: "handles URL with port",
			cfg: model.Service{
				Mode: model.ServiceModeDiscovery,
				Repository: &model.Repository{
					URL: mustParseURL(t, "http://example.com"),
				},
				Seeker: &model.SeekerServer{
					BaseURL:   mustParseURL(t, "http://localhost:9090"),
					StateFile: ":memory:",
				},
				Core: &model.Core{
					BaseURL: mustParseURL(t, "http://core.example.com:8080"),
				},
			},
			setupSv: true,
			jobName: "test-job",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			var sv *service.Supervisor
			if tt.setupSv {
				var err error
				sv, err = service.NewSupervisor(ctx, model.Config{
					Service: model.Service{Mode: model.ServiceModeDiscovery},
				})
				require.NoError(t, err)
			}

			server, err := New(ctx, tt.cfg, sv, tt.jobName)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
				require.Nil(t, server)
			} else {
				require.NoError(t, err)
				require.NotNil(t, server)
				require.Equal(t, tt.jobName, server.jobName)
				require.NotNil(t, server.db)
				require.Equal(t, functionalGroupCode, server.funcGroupCode)
				require.False(t, server.runningFlag)
				require.Empty(t, server.uuid)

				// Verify path trimming
				require.False(t, strings.HasSuffix(server.cfg.Seeker.BaseURL.Path, "/"))
				require.False(t, strings.HasSuffix(server.cfg.Core.BaseURL.Path, "/"))

				// Cleanup
				_ = server.db.Close()
			}
		})
	}
}

func TestHTTPInfoContext(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		urlPath      string
		expectCalled bool
		validateCtx  func(*testing.T, context.Context)
	}{
		{
			name:         "GET request with root path",
			method:       http.MethodGet,
			urlPath:      "/",
			expectCalled: true,
			validateCtx: func(t *testing.T, ctx context.Context) {
				require.NotNil(t, ctx)
				// Context should have been modified by log.ContextAttrs
				require.NotEqual(t, context.Background(), ctx)
			},
		},
		{
			name:         "POST request with nested path",
			method:       http.MethodPost,
			urlPath:      "/api/v1/users",
			expectCalled: true,
			validateCtx: func(t *testing.T, ctx context.Context) {
				require.NotNil(t, ctx)
			},
		},
		{
			name:         "PUT request",
			method:       http.MethodPut,
			urlPath:      "/resource/123",
			expectCalled: true,
			validateCtx: func(t *testing.T, ctx context.Context) {
				require.NotNil(t, ctx)
			},
		},
		{
			name:         "DELETE request",
			method:       http.MethodDelete,
			urlPath:      "/items/456",
			expectCalled: true,
			validateCtx: func(t *testing.T, ctx context.Context) {
				require.NotNil(t, ctx)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Track if next handler was called
			nextCalled := false
			var capturedCtx context.Context

			// Create mock next handler
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				capturedCtx = r.Context()
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with middleware
			handler := httpInfoContext(nextHandler)

			// Create test request
			req := httptest.NewRequest(tt.method, tt.urlPath, nil)
			w := httptest.NewRecorder()

			// Execute handler
			handler.ServeHTTP(w, req)

			// Verify next handler was called
			require.Equal(t, tt.expectCalled, nextCalled, "next handler should be called")

			// Validate context was modified
			if tt.validateCtx != nil {
				tt.validateCtx(t, capturedCtx)
			}

			// Verify response
			require.Equal(t, http.StatusOK, w.Code)
		})
	}
}

func TestServer_startIf(t *testing.T) {
	tests := []struct {
		name          string
		setupServer   func(t *testing.T) *Server
		dscvrUUID     string
		want          bool
		wantErr       bool
		checkRunning  bool
		expectedUUID  string
		storeStartErr bool
	}{
		{
			name: "start when not running",
			setupServer: func(t *testing.T) *Server {
				return createTestServer(t, false, "")
			},
			dscvrUUID:    "test-uuid-123",
			want:         true,
			wantErr:      false,
			checkRunning: true,
			expectedUUID: "test-uuid-123",
		},
		{
			name: "cannot start when already running",
			setupServer: func(t *testing.T) *Server {
				return createTestServer(t, true, "existing-uuid")
			},
			dscvrUUID:    "new-uuid-456",
			want:         false,
			wantErr:      false,
			checkRunning: true,
			expectedUUID: "existing-uuid",
		},
		{
			name: "start same UUID twice in a row",
			setupServer: func(t *testing.T) *Server {
				s := createTestServer(t, false, "")
				// Start first time
				ctx := context.Background()
				started, err := s.startIf(ctx, "uuid-same")
				require.NoError(t, err)
				require.True(t, started)
				return s
			},
			dscvrUUID:    "uuid-same",
			want:         false,
			wantErr:      false,
			checkRunning: true,
			expectedUUID: "uuid-same",
		},
		{
			name: "handles empty UUID",
			setupServer: func(t *testing.T) *Server {
				return createTestServer(t, false, "")
			},
			dscvrUUID:    "",
			want:         true,
			wantErr:      false,
			checkRunning: true,
			expectedUUID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			s := tt.setupServer(t)
			defer func() {
				_ = s.db.Close()
			}()

			got, err := s.startIf(ctx, tt.dscvrUUID)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, tt.want, got)

			if tt.checkRunning {
				s.mx.Lock()
				if tt.want {
					require.True(t, s.runningFlag)
				}
				require.Equal(t, tt.expectedUUID, s.uuid)
				s.mx.Unlock()
			}
		})
	}
}

func TestServer_UploadedCallback(t *testing.T) {
	tests := []struct {
		name          string
		setupServer   func(t *testing.T) *Server
		callbackErr   error
		jobName       string
		id            string
		expectRunning bool
		expectUUID    string
		setupUUID     string
	}{
		{
			name: "successful upload - matching job name",
			setupServer: func(t *testing.T) *Server {
				s := createTestServer(t, true, "test-uuid")
				s.jobName = "test-job"
				return s
			},
			callbackErr:   nil,
			jobName:       "test-job",
			id:            "cert-123",
			expectRunning: false,
			expectUUID:    "",
			setupUUID:     "test-uuid",
		},
		{
			name: "failed upload - matching job name",
			setupServer: func(t *testing.T) *Server {
				s := createTestServer(t, true, "test-uuid-fail")
				s.jobName = "test-job"
				return s
			},
			callbackErr:   fmt.Errorf("upload failed"),
			jobName:       "test-job",
			id:            "cert-456",
			expectRunning: false,
			expectUUID:    "",
			setupUUID:     "test-uuid-fail",
		},
		{
			name: "non-matching job name",
			setupServer: func(t *testing.T) *Server {
				s := createTestServer(t, true, "test-uuid-nomatch")
				s.jobName = "test-job"
				return s
			},
			callbackErr:   nil,
			jobName:       "different-job",
			id:            "cert-789",
			expectRunning: true,
			expectUUID:    "test-uuid-nomatch",
			setupUUID:     "test-uuid-nomatch",
		},
		{
			name: "callback when not running",
			setupServer: func(t *testing.T) *Server {
				s := createTestServer(t, false, "")
				s.jobName = "test-job"
				return s
			},
			callbackErr:   nil,
			jobName:       "test-job",
			id:            "cert-abc",
			expectRunning: false,
			expectUUID:    "",
			setupUUID:     "",
		},
		{
			name: "successful callback with empty job name",
			setupServer: func(t *testing.T) *Server {
				s := createTestServer(t, true, "test-uuid-empty")
				s.jobName = ""
				return s
			},
			callbackErr:   nil,
			jobName:       "",
			id:            "cert-empty",
			expectRunning: false,
			expectUUID:    "",
			setupUUID:     "test-uuid-empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			s := tt.setupServer(t)
			defer func() {
				_ = s.db.Close()
			}()

			// Setup discovery in store if UUID is set
			if tt.setupUUID != "" {
				err := store.Start(ctx, s.db, tt.setupUUID)
				require.NoError(t, err)
			}

			s.UploadedCallback(tt.callbackErr, tt.jobName, tt.id)

			s.mx.Lock()
			require.Equal(t, tt.expectRunning, s.runningFlag)
			require.Equal(t, tt.expectUUID, s.uuid)
			s.mx.Unlock()
		})
	}
}

func TestServer_Handler(t *testing.T) {
	tests := []struct {
		name           string
		setupServer    func(t *testing.T) *Server
		checkEndpoints bool
	}{
		{
			name: "creates handler with all endpoints",
			setupServer: func(t *testing.T) *Server {
				return createTestServer(t, false, "")
			},
			checkEndpoints: true,
		},
		{
			name: "handler with custom base path",
			setupServer: func(t *testing.T) *Server {
				s := createTestServer(t, false, "")
				s.cfg.Seeker.BaseURL.Path = "/custom/path"
				return s
			},
			checkEndpoints: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.setupServer(t)
			defer func() {
				_ = s.db.Close()
			}()

			mux := s.Handler()
			require.NotNil(t, mux)

			if tt.checkEndpoints {
				endpoints := DiscoveryProviderEndpoints()
				require.NotEmpty(t, endpoints)
				require.Len(t, endpoints, 7)

				// Verify all expected endpoints are present
				expectedKeys := []string{
					"checkHealth",
					"listSupportedFunctions",
					"listAttributeDefinitions",
					"validateAttributes",
					"deleteDiscovery",
					"discoverCertificate",
					"getDiscovery",
				}
				for _, key := range expectedKeys {
					_, exists := endpoints[key]
					require.True(t, exists, "endpoint %s should exist", key)
				}
			}
		})
	}
}

func TestServer_RegisterConnector(t *testing.T) {
	tests := []struct {
		name        string
		setupServer func(t *testing.T, serverURL string) *Server
		mockServer  func(t *testing.T) *httptest.Server
		wantErr     bool
		errContains string
	}{
		{
			name: "successful registration - status OK",
			setupServer: func(t *testing.T, serverURL string) *Server {
				s := createTestServer(t, false, "")
				coreURL, err := url.Parse(serverURL)
				require.NoError(t, err)
				s.cfg.Core = &model.Core{BaseURL: model.URL{URL: coreURL}}
				s.cfg.Seeker = &model.SeekerServer{
					BaseURL: mustParseURL(t, "http://localhost:8080"),
				}
				return s
			},
			mockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, http.MethodPost, r.Method)
					require.Equal(t, "application/json", r.Header.Get("Content-Type"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
				}))
			},
			wantErr: false,
		},
		{
			name: "already registered - status bad request with message",
			setupServer: func(t *testing.T, serverURL string) *Server {
				s := createTestServer(t, false, "")
				coreURL, err := url.Parse(serverURL)
				require.NoError(t, err)
				s.cfg.Core = &model.Core{BaseURL: model.URL{URL: coreURL}}
				s.cfg.Seeker = &model.SeekerServer{
					BaseURL: mustParseURL(t, "http://localhost:8080"),
				}
				return s
			},
			mockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					require.NoError(t, json.NewEncoder(w).Encode(map[string]string{
						"message": "Connector already exists",
					}))
				}))
			},
			wantErr: false,
		},
		{
			name: "already registered - status not found",
			setupServer: func(t *testing.T, serverURL string) *Server {
				s := createTestServer(t, false, "")
				coreURL, err := url.Parse(serverURL)
				require.NoError(t, err)
				s.cfg.Core = &model.Core{BaseURL: model.URL{URL: coreURL}}
				s.cfg.Seeker = &model.SeekerServer{
					BaseURL: mustParseURL(t, "http://localhost:8080"),
				}
				return s
			},
			mockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					require.NoError(t, json.NewEncoder(w).Encode(map[string]string{
						"message": "already exists in system",
					}))
				}))
			},
			wantErr: false,
		},
		{
			name: "already registered - status unprocessable entity",
			setupServer: func(t *testing.T, serverURL string) *Server {
				s := createTestServer(t, false, "")
				coreURL, err := url.Parse(serverURL)
				require.NoError(t, err)
				s.cfg.Core = &model.Core{BaseURL: model.URL{URL: coreURL}}
				s.cfg.Seeker = &model.SeekerServer{
					BaseURL: mustParseURL(t, "http://localhost:8080"),
				}
				return s
			},
			mockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnprocessableEntity)
					require.NoError(t, json.NewEncoder(w).Encode([]string{
						"Connector(s) with same kinds already exists: test",
					}))
				}))
			},
			wantErr: false,
		},
		{
			name: "registration error - bad request without already exists",
			setupServer: func(t *testing.T, serverURL string) *Server {
				s := createTestServer(t, false, "")
				coreURL, err := url.Parse(serverURL)
				require.NoError(t, err)
				s.cfg.Core = &model.Core{BaseURL: model.URL{URL: coreURL}}
				s.cfg.Seeker = &model.SeekerServer{
					BaseURL: mustParseURL(t, "http://localhost:8080"),
				}
				return s
			},
			mockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					require.NoError(t, json.NewEncoder(w).Encode(map[string]string{
						"message": "invalid request payload",
					}))
				}))
			},
			wantErr:     true,
			errContains: "status code: 400",
		},
		{
			name: "registration error - not found without already exists",
			setupServer: func(t *testing.T, serverURL string) *Server {
				s := createTestServer(t, false, "")
				coreURL, err := url.Parse(serverURL)
				require.NoError(t, err)
				s.cfg.Core = &model.Core{BaseURL: model.URL{URL: coreURL}}
				s.cfg.Seeker = &model.SeekerServer{
					BaseURL: mustParseURL(t, "http://localhost:8080"),
				}
				return s
			},
			mockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					require.NoError(t, json.NewEncoder(w).Encode(map[string]string{
						"message": "endpoint not found",
					}))
				}))
			},
			wantErr:     true,
			errContains: "status code: 404",
		},
		{
			name: "registration error - bad request non-json response",
			setupServer: func(t *testing.T, serverURL string) *Server {
				s := createTestServer(t, false, "")
				coreURL, err := url.Parse(serverURL)
				require.NoError(t, err)
				s.cfg.Core = &model.Core{BaseURL: model.URL{URL: coreURL}}
				s.cfg.Seeker = &model.SeekerServer{
					BaseURL: mustParseURL(t, "http://localhost:8080"),
				}
				return s
			},
			mockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte("bad request"))
				}))
			},
			wantErr:     true,
			errContains: "status code 400",
		},
		{
			name: "registration error - unprocessable entity without already exists",
			setupServer: func(t *testing.T, serverURL string) *Server {
				s := createTestServer(t, false, "")
				coreURL, err := url.Parse(serverURL)
				require.NoError(t, err)
				s.cfg.Core = &model.Core{BaseURL: model.URL{URL: coreURL}}
				s.cfg.Seeker = &model.SeekerServer{
					BaseURL: mustParseURL(t, "http://localhost:8080"),
				}
				return s
			},
			mockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnprocessableEntity)
					require.NoError(t, json.NewEncoder(w).Encode([]string{
						"validation error 1",
						"validation error 2",
					}))
				}))
			},
			wantErr:     true,
			errContains: "validation error",
		},
		{
			name: "registration error - unprocessable entity non-json",
			setupServer: func(t *testing.T, serverURL string) *Server {
				s := createTestServer(t, false, "")
				coreURL, err := url.Parse(serverURL)
				require.NoError(t, err)
				s.cfg.Core = &model.Core{BaseURL: model.URL{URL: coreURL}}
				s.cfg.Seeker = &model.SeekerServer{
					BaseURL: mustParseURL(t, "http://localhost:8080"),
				}
				return s
			},
			mockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusUnprocessableEntity)
					_, _ = w.Write([]byte("unprocessable"))
				}))
			},
			wantErr:     true,
			errContains: "status code 422",
		},
		{
			name: "unexpected status code",
			setupServer: func(t *testing.T, serverURL string) *Server {
				s := createTestServer(t, false, "")
				coreURL, err := url.Parse(serverURL)
				require.NoError(t, err)
				s.cfg.Core = &model.Core{BaseURL: model.URL{URL: coreURL}}
				s.cfg.Seeker = &model.SeekerServer{
					BaseURL: mustParseURL(t, "http://localhost:8080"),
				}
				return s
			},
			mockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
			},
			wantErr:     true,
			errContains: "unexpected status code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mockSrv := tt.mockServer(t)
			defer mockSrv.Close()

			s := tt.setupServer(t, mockSrv.URL)
			defer func() {
				_ = s.db.Close()
			}()

			err := s.RegisterConnector(ctx)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDecodeRegisterResponse(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		body        interface{}
		wantErr     bool
		errContains string
	}{
		{
			name:        "status OK",
			statusCode:  http.StatusOK,
			contentType: "application/json",
			body:        nil,
			wantErr:     false,
		},
		{
			name:        "bad request with already exists message",
			statusCode:  http.StatusBadRequest,
			contentType: "application/json",
			body:        map[string]string{"message": "Connector already exists"},
			wantErr:     false,
		},
		{
			name:        "bad request with error message",
			statusCode:  http.StatusBadRequest,
			contentType: "application/json",
			body:        map[string]string{"message": "invalid request"},
			wantErr:     true,
			errContains: "invalid request",
		},
		{
			name:        "bad request without json",
			statusCode:  http.StatusBadRequest,
			contentType: "text/plain",
			body:        "error",
			wantErr:     true,
			errContains: "status code 400",
		},
		{
			name:        "bad request with invalid json",
			statusCode:  http.StatusBadRequest,
			contentType: "application/json",
			body:        "invalid-json",
			wantErr:     true,
			errContains: "status code 400",
		},
		{
			name:        "not found with already exists",
			statusCode:  http.StatusNotFound,
			contentType: "application/json",
			body:        map[string]string{"message": "already exists somewhere"},
			wantErr:     false,
		},
		{
			name:        "not found with error",
			statusCode:  http.StatusNotFound,
			contentType: "application/json",
			body:        map[string]string{"message": "resource not found"},
			wantErr:     true,
			errContains: "resource not found",
		},
		{
			name:        "unprocessable entity with already exists",
			statusCode:  http.StatusUnprocessableEntity,
			contentType: "application/json",
			body:        []string{"Connector already exists: test"},
			wantErr:     false,
		},
		{
			name:        "unprocessable entity with error",
			statusCode:  http.StatusUnprocessableEntity,
			contentType: "application/json",
			body:        []string{"validation error 1", "validation error 2"},
			wantErr:     true,
			errContains: "validation error",
		},
		{
			name:        "unprocessable entity without json",
			statusCode:  http.StatusUnprocessableEntity,
			contentType: "text/plain",
			body:        "error",
			wantErr:     true,
			errContains: "status code 422",
		},
		{
			name:        "unprocessable entity with invalid json",
			statusCode:  http.StatusUnprocessableEntity,
			contentType: "application/json",
			body:        "not-an-array",
			wantErr:     true,
			errContains: "status code 422",
		},
		{
			name:        "unexpected status code",
			statusCode:  http.StatusInternalServerError,
			contentType: "application/json",
			body:        nil,
			wantErr:     true,
			errContains: "unexpected status code",
		},
		{
			name:        "status created",
			statusCode:  http.StatusCreated,
			contentType: "application/json",
			body:        nil,
			wantErr:     true,
			errContains: "unexpected status code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			rec := httptest.NewRecorder()
			rec.WriteHeader(tt.statusCode)

			if tt.body != nil {
				switch v := tt.body.(type) {
				case string:
					_, _ = rec.WriteString(v)
				default:
					t.Log("ano, je to json")
					err := json.NewEncoder(rec).Encode(tt.body)
					require.NoError(t, err)
				}
			}

			resp := rec.Result()
			defer func() {
				_ = resp.Body.Close()
			}()

			if tt.contentType != "" {
				resp.Header["Content-Type"] = []string{tt.contentType}
			}

			err := decodeRegisterResponse(ctx, resp)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// Helper functions

func createTestServer(t *testing.T, running bool, uuid string) *Server {
	ctx := context.Background()
	db, err := store.InitDB(ctx, ":memory:")
	require.NoError(t, err)

	sv, err := service.NewSupervisor(ctx, model.Config{
		Service: model.Service{Mode: model.ServiceModeDiscovery},
	})
	require.NoError(t, err)

	s := &Server{
		cfg: model.Service{
			Mode: model.ServiceModeDiscovery,
			Seeker: &model.SeekerServer{
				BaseURL:   mustParseURL(t, "http://localhost:8080"),
				StateFile: ":memory:",
			},
			Core: &model.Core{
				BaseURL: mustParseURL(t, "http://core.example.com"),
			},
		},
		sv:            sv,
		kind:          "test-kind",
		funcGroupCode: functionalGroupCode,
		jobName:       "test-job",
		db:            db,
		runningFlag:   running,
		uuid:          uuid,
	}

	return s
}

func mustParseURL(t *testing.T, rawURL string) model.URL {
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return model.URL{URL: u}
}
