package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"edr-backend/platform/internal/ingestcommand"
	"edr-backend/platform/internal/repo"

	"github.com/gin-gonic/gin"
)

type mockForensicStore struct {
	getFn func(ctx context.Context, tenantID, endpointID string) (*repo.EndpointRow, error)
}

func (m *mockForensicStore) Get(ctx context.Context, tenantID, endpointID string) (*repo.EndpointRow, error) {
	if m.getFn != nil {
		return m.getFn(ctx, tenantID, endpointID)
	}
	return nil, nil
}

func newTestForensicHandler(mock *mockForensicStore, broker *ingestcommand.Broker) *ForensicP2Handler {
	return &ForensicP2Handler{repo: mock, cmdBroker: broker}
}

func TestPostDeepForensic_MissingScope(t *testing.T) {
	broker := ingestcommand.NewBroker()
	mock := &mockForensicStore{
		getFn: func(ctx context.Context, tenantID, endpointID string) (*repo.EndpointRow, error) {
			return &repo.EndpointRow{ID: endpointID}, nil
		},
	}
	sh := newTestForensicHandler(mock, broker)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/endpoints/:id/forensic/deep", sh.PostDeepForensic)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/ep-1/forensic/deep", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing scope, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestPostDeepForensic_ScopeOutOfRange(t *testing.T) {
	broker := ingestcommand.NewBroker()
	mock := &mockForensicStore{
		getFn: func(ctx context.Context, tenantID, endpointID string) (*repo.EndpointRow, error) {
			return &repo.EndpointRow{ID: endpointID}, nil
		},
	}
	sh := newTestForensicHandler(mock, broker)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/endpoints/:id/forensic/deep", sh.PostDeepForensic)

	for _, scope := range []int{0, 4} {
		pl, _ := json.Marshal(map[string]int{"scope": scope})
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/ep-1/forensic/deep", bytes.NewReader(pl))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("scope=%d: expected 400, got %d body=%s", scope, w.Code, w.Body.String())
		}
	}
}

func TestPostDeepForensic_Success(t *testing.T) {
	broker := ingestcommand.NewBroker()
	recv, detach := broker.Attach("ep-1")
	defer detach()

	mock := &mockForensicStore{
		getFn: func(ctx context.Context, tenantID, endpointID string) (*repo.EndpointRow, error) {
			return &repo.EndpointRow{ID: endpointID}, nil
		},
	}
	sh := newTestForensicHandler(mock, broker)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/endpoints/:id/forensic/deep", sh.PostDeepForensic)

	pl, _ := json.Marshal(map[string]int{"scope": 2})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/ep-1/forensic/deep", bytes.NewReader(pl))
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
		if env.GetCommandType() != "forensic_deep" {
			t.Fatalf("expected command_type=forensic_deep, got %s", env.GetCommandType())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for CommandEnvelope on broker")
	}
}
