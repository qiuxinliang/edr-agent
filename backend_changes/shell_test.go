package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"edr-backend/platform/internal/ingestcommand"
	"edr-backend/platform/internal/repo"

	"github.com/gin-gonic/gin"
)

type mockEndpointStore struct {
	getFn func(ctx context.Context, tenantID, endpointID string) (*repo.EndpointRow, error)
}

func (m *mockEndpointStore) Get(ctx context.Context, tenantID, endpointID string) (*repo.EndpointRow, error) {
	if m.getFn != nil {
		return m.getFn(ctx, tenantID, endpointID)
	}
	return nil, sql.ErrNoRows
}

func newTestShellHandler(mock *mockEndpointStore, broker *ingestcommand.Broker) *ShellHandler {
	return &ShellHandler{repo: mock, cmdBroker: broker}
}

func okMock() *mockEndpointStore {
	return &mockEndpointStore{
		getFn: func(ctx context.Context, tenantID, ep string) (*repo.EndpointRow, error) {
			return &repo.EndpointRow{ID: ep}, nil
		},
	}
}

func TestPostShellOpen_MissingEndpointID(t *testing.T) {
	broker := ingestcommand.NewBroker()
	sh := newTestShellHandler(&mockEndpointStore{}, broker)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/endpoints/:id/shell/open", sh.PostShellOpen)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints//shell/open", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestPostShellOpen_EndpointNotFound(t *testing.T) {
	broker := ingestcommand.NewBroker()
	mock := &mockEndpointStore{
		getFn: func(ctx context.Context, tenantID, endpointID string) (*repo.EndpointRow, error) {
			return nil, sql.ErrNoRows
		},
	}
	sh := newTestShellHandler(mock, broker)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/endpoints/:id/shell/open", sh.PostShellOpen)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/ep-1/shell/open", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestPostShellOpen_Success(t *testing.T) {
	broker := ingestcommand.NewBroker()
	recv, detach := broker.Attach("ep-1")
	defer detach()

	sh := newTestShellHandler(okMock(), broker)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/endpoints/:id/shell/open", sh.PostShellOpen)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/ep-1/shell/open", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	data, ok := envelope["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing data in response: %s", w.Body.String())
	}
	if data["status"] != "dispatched" {
		t.Fatalf("expected status=dispatched, got %v", data["status"])
	}

	select {
	case env := <-recv:
		if env.GetCommandType() != "shell_open" {
			t.Fatalf("expected command_type=shell_open, got %s", env.GetCommandType())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for CommandEnvelope on broker")
	}
}

func TestPostShellInput_MissingSessionID(t *testing.T) {
	broker := ingestcommand.NewBroker()
	sh := newTestShellHandler(okMock(), broker)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/endpoints/:id/shell/input", sh.PostShellInput)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/ep-1/shell/input", bytes.NewReader([]byte(`{"input":"dir"}`)))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing session_id, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestPostShellInput_MissingInput(t *testing.T) {
	broker := ingestcommand.NewBroker()
	sh := newTestShellHandler(okMock(), broker)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/endpoints/:id/shell/input", sh.PostShellInput)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/ep-1/shell/input", bytes.NewReader([]byte(`{"session_id":"0"}`)))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing input, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestPostShellInput_Success(t *testing.T) {
	broker := ingestcommand.NewBroker()
	recv, detach := broker.Attach("ep-1")
	defer detach()

	sh := newTestShellHandler(okMock(), broker)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/endpoints/:id/shell/input", sh.PostShellInput)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/ep-1/shell/input", bytes.NewReader([]byte(`{"session_id":"0","input":"dir"}`)))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	select {
	case env := <-recv:
		if env.GetCommandType() != "shell_input" {
			t.Fatalf("expected command_type=shell_input, got %s", env.GetCommandType())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for CommandEnvelope on broker")
	}
}

func TestPostShellClose_MissingSessionID(t *testing.T) {
	broker := ingestcommand.NewBroker()
	sh := newTestShellHandler(okMock(), broker)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/endpoints/:id/shell/close", sh.PostShellClose)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/ep-1/shell/close", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing session_id, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestPostShellClose_Success(t *testing.T) {
	broker := ingestcommand.NewBroker()
	recv, detach := broker.Attach("ep-1")
	defer detach()

	sh := newTestShellHandler(okMock(), broker)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/endpoints/:id/shell/close", sh.PostShellClose)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/ep-1/shell/close", bytes.NewReader([]byte(`{"session_id":"0"}`)))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	select {
	case env := <-recv:
		if env.GetCommandType() != "shell_close" {
			t.Fatalf("expected command_type=shell_close, got %s", env.GetCommandType())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for CommandEnvelope on broker")
	}
}
