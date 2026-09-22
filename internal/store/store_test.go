package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLitePersistenceAndFeedback(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "triage.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Now()
	if e = s.SaveIncident(context.Background(), map[string]string{"x": "y"}, "i1", "r|a|ip", "medium", 50, 2, now, now); e != nil {
		t.Fatal(e)
	}
	if e = s.AddFeedback(context.Background(), "i1", "fp", "noise", "analyst"); e != nil {
		t.Fatal(e)
	}
}
