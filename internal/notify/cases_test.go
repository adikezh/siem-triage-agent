package notify

import (
	"context"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTheHiveAndIRIS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-thehive-user") != "h" && r.Header.Get("x-iris-api-key") != "i" {
			t.Fatal("missing API key")
		}
		w.WriteHeader(201)
	}))
	defer srv.Close()
	if e := (TheHive{URL: srv.URL, APIKey: "h"}).Send(context.Background(), store.OutboxItem{IncidentID: "a", Payload: []byte("x")}); e != nil {
		t.Fatal(e)
	}
	if e := (IRIS{URL: srv.URL, APIKey: "i"}).Send(context.Background(), store.OutboxItem{IncidentID: "b", Payload: []byte("x")}); e != nil {
		t.Fatal(e)
	}
}
