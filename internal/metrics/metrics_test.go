package metrics

import (
	"context"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHandler(t *testing.T) {
	s, _ := store.Open(filepath.Join(t.TempDir(), "m.db"))
	defer s.Close()
	n := time.Now()
	_ = s.SaveIncident(context.Background(), map[string]string{}, "i", "f", "critical", 90, 1, n, n)
	w := httptest.NewRecorder()
	Handler(s).ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(w.Body.String(), `triage_incidents_total{severity="critical"} 1`) {
		t.Fatal(w.Body.String())
	}
}
