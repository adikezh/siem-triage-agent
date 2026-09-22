package report

import (
	"context"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMarkdown(t *testing.T) {
	s, e := store.Open(filepath.Join(t.TempDir(), "r.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	n := time.Now().UTC()
	if e = s.SaveIncident(context.Background(), map[string]string{"x": "y"}, "i", "f", "high", 70, 1, n, n); e != nil {
		t.Fatal(e)
	}
	m, e := Markdown(context.Background(), s, 24*time.Hour)
	if e != nil || !strings.Contains(m, "Total incidents: **1**") || !strings.Contains(m, "| high | 1 |") {
		t.Fatalf("%s %v", m, e)
	}
}
