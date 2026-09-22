package web

import (
	"context"
	"github.com/adikezh/siem-triage-agent/internal/store"
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
	if w.Code != 200 || !strings.Contains(w.Body.String(), "rule|agent|ip") || !strings.Contains(w.Body.String(), "high") {
		t.Fatalf("dashboard %d %s", w.Code, w.Body.String())
	}
}
