package realtime

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type subscriber struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (s *subscriber) writeText(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
	return s.conn.WriteMessage(websocket.TextMessage, b)
}

type Hub struct {
	mu      sync.RWMutex
	tenants map[string]map[*subscriber]struct{}
}

func NewHub() *Hub {
	return &Hub{tenants: make(map[string]map[*subscriber]struct{})}
}

func (h *Hub) Register(tenantID string, conn *websocket.Conn) (unregister func()) {
	sub := &subscriber{conn: conn}
	h.mu.Lock()
	m := h.tenants[tenantID]
	if m == nil {
		m = make(map[*subscriber]struct{})
		h.tenants[tenantID] = m
	}
	m[sub] = struct{}{}
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		if m := h.tenants[tenantID]; m != nil {
			delete(m, sub)
			if len(m) == 0 {
				delete(h.tenants, tenantID)
			}
		}
		h.mu.Unlock()
		_ = conn.Close()
	}
}

func (h *Hub) BroadcastAlert(tenantID string, alert map[string]any, total int) {
	payload := map[string]any{"type": "alert:new", "alert": alert, "total": total}
	h.broadcastPayload(tenantID, payload)
}

func (h *Hub) BroadcastAlertUpdate(tenantID string, alert map[string]any, total int) {
	if h == nil || strings.TrimSpace(tenantID) == "" || len(alert) == 0 {
		return
	}
	payload := map[string]any{"type": "alert:update", "alert": alert, "total": total}
	h.broadcastPayload(tenantID, payload)
}

func (h *Hub) BroadcastEvent(tenantID, event string, payload any) {
	if h == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(event) == "" {
		return
	}
	body := map[string]any{"type": event, "payload": payload}
	h.broadcastPayload(tenantID, body)
}

func (h *Hub) BroadcastSoar(tenantID, typ string, payload any) {
	if h == nil || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(typ) == "" {
		return
	}
	body := map[string]any{"type": typ, "tenant_id": tenantID, "payload": payload}
	h.broadcastPayload(tenantID, body)
}

func (h *Hub) BroadcastShellOutput(endpointID string, output string, isStderr bool) {
	if h == nil || strings.TrimSpace(endpointID) == "" {
		return
	}
	payload := map[string]any{
		"type":        "shell:output",
		"endpoint_id": endpointID,
		"output":      output,
		"is_stderr":   isStderr,
		"ts":          time.Now().UTC().Format(time.RFC3339Nano),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for tenantID, subs := range h.tenants {
		_ = tenantID
		for s := range subs {
			_ = s.writeText(b)
		}
	}
}

func (h *Hub) broadcastPayload(tenantID string, payload map[string]any) {
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	h.mu.RLock()
	m := h.tenants[tenantID]
	subs := make([]*subscriber, 0, len(m))
	for s := range m {
		subs = append(subs, s)
	}
	h.mu.RUnlock()
	for _, s := range subs {
		_ = s.writeText(b)
	}
}
