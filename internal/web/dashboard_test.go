package web

import (
	"context"
	"github.com/adikezh/siem-triage-agent/internal/enrich"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDashboard(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	n := time.Now()
	_ = s.SaveIncident(context.Background(), map[string]string{}, "i", "rule|agent|ip", "high", 70, 2, n, n)
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	Handler(s).ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "rule|agent|ip") || !strings.Contains(w.Body.String(), "high") || !strings.Contains(w.Body.String(), "/incidents/i") {
		t.Fatalf("dashboard %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest("GET", "/stats", nil)
	w = httptest.NewRecorder()
	Handler(s).ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Dashboard") || !strings.Contains(w.Body.String(), "Total: 1") || !strings.Contains(w.Body.String(), "high") {
		t.Fatalf("stats dashboard %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest("GET", "/?severity=low", nil)
	w = httptest.NewRecorder()
	Handler(s).ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "rule|agent|ip") {
		t.Fatalf("severity filter failed: %d %s", w.Code, w.Body.String())
	}
}

func TestIncidentDetailAndFeedback(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	n := time.Now()
	if err = s.SaveIncident(context.Background(), map[string]string{"event": "test"}, "inc-1", "fp", "high", 80, 1, n, n); err != nil {
		t.Fatal(err)
	}
	h := Handler(s)
	r := httptest.NewRequest("GET", "/incidents/inc-1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Incident payload") {
		t.Fatalf("detail %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest("POST", "/incidents/inc-1/feedback", strings.NewReader("verdict=fp"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("feedback %d %s", w.Code, w.Body.String())
	}
	rows, err := s.ListFeedback(context.Background())
	if err != nil || len(rows) != 1 || rows[0].Verdict != "fp" {
		t.Fatalf("feedback=%#v err=%v", rows, err)
	}
}

func TestAssetsAndSuppressionsPages(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "pages.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.CreateSuppression(context.Background(), "rule|agent|ip", "drop", "known noise", "", "analyst"); err != nil {
		t.Fatal(err)
	}
	h := HandlerWithAssets(s, map[string]enrich.Asset{"10.0.0.10": {IP: "10.0.0.10", Hostname: "db-1", Criticality: 5}})
	for _, tc := range []struct{ path, want string }{{"/suppressions", "known noise"}, {"/assets", "db-1"}} {
		r := httptest.NewRequest("GET", tc.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), tc.want) {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
}
