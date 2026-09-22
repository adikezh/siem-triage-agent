package notify

import (
	"context"
	"encoding/json"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJiraSender(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "u" || p != "t" {
			t.Fatal("missing basic auth")
		}
		var v map[string]any
		if e := json.NewDecoder(r.Body).Decode(&v); e != nil {
			t.Fatal(e)
		}
		if _, ok := v["fields"]; !ok {
			t.Fatal("fields missing")
		}
		w.WriteHeader(201)
	}))
	defer srv.Close()
	j := Jira{BaseURL: srv.URL, Username: "u", Token: "t", Project: "SOC"}
	if e := j.Send(context.Background(), store.OutboxItem{IncidentID: "i", Payload: []byte("details")}); e != nil {
		t.Fatal(e)
	}
}
