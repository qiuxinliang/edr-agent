package realtime

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestBroadcastShellOutput_ConnectedClientReceives(t *testing.T) {
	hub := NewHub()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade: %v", err)
		}
		unreg := hub.Register("t1", conn)
		defer unreg()

		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	d := websocket.DefaultDialer
	client, _, err := d.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	time.Sleep(100 * time.Millisecond)

	hub.BroadcastShellOutput("ep-1", "C:\\Users>", false)

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := client.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(msg, &out); err != nil {
		t.Fatalf("unmarshal: %v, raw=%s", err, string(msg))
	}

	if tp, _ := out["type"].(string); tp != "shell:output" {
		t.Fatalf("expected type=shell:output, got type=%v", out["type"])
	}
	if eid, _ := out["endpoint_id"].(string); eid != "ep-1" {
		t.Fatalf("expected endpoint_id=ep-1, got %v", out["endpoint_id"])
	}
	if op, _ := out["output"].(string); !strings.Contains(op, "C:\\Users") {
		t.Fatalf("expected output containing C:\\Users, got %v", out["output"])
	}
	if st, _ := out["is_stderr"].(bool); st != false {
		t.Fatalf("expected is_stderr=false, got %v", out["is_stderr"])
	}
}
