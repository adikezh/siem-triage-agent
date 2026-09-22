package notify

import (
	"context"
	"encoding/json"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSlackSenderBlockKit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v map[string]any
		if e := json.NewDecoder(r.Body).Decode(&v); e != nil {
			t.Fatal(e)
		}
		blocks, ok := v["blocks"].([]any)
		if !ok || len(blocks) < 2 {
			t.Fatal("blocks missing")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	if e := (Slack{URL: srv.URL}).Send(context.Background(), store.OutboxItem{IncidentID: "inc-1", Payload: []byte("incident")}); e != nil {
		t.Fatal(e)
	}
}
