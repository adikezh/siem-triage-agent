package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAnalystWritesRollbackWithAuditFailure(t *testing.T) {
	for _, operation := range []string{"feedback", "create", "delete"} {
		t.Run(operation, func(t *testing.T) {
			s, err := Open(filepath.Join(t.TempDir(), "audit.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx := context.Background()
			n := time.Now()
			if err = s.SaveIncident(ctx, map[string]string{}, "i", "fp", "high", 80, 1, n, n); err != nil {
				t.Fatal(err)
			}
			rule, err := s.CreateSuppression(ctx, "fp", "tag", "fixture", "", "analyst")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.db.Exec(`CREATE TRIGGER audit_failure BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END`); err != nil {
				t.Fatal(err)
			}
			switch operation {
			case "feedback":
				err = s.AddFeedback(ctx, "i", "fp", "", "analyst")
			case "create":
				_, err = s.CreateSuppression(ctx, "another", "tag", "fixture", "", "analyst")
			case "delete":
				err = s.DeleteSuppressionBy(ctx, rule.ID, "admin")
			}
			if err == nil {
				t.Fatal("injected audit failure ignored")
			}
			feedback, e := s.ListFeedback(ctx)
			if e != nil || len(feedback) != 0 {
				t.Fatalf("feedback partially persisted: %+v %v", feedback, e)
			}
			rules, e := s.ListSuppressions(ctx)
			if e != nil || len(rules) != 1 || rules[0].ID != rule.ID {
				t.Fatalf("rule mutation partially persisted: %+v %v", rules, e)
			}
			if e = s.VerifyAuditChain(ctx); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestConcurrentFeedbackAuditChain(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	n := time.Now()
	if err = s.SaveIncident(ctx, map[string]string{}, "i", "fp", "high", 80, 1, n, n); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := s.AddFeedback(ctx, "i", "fp", "fixture", "analyst"); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if err = s.VerifyAuditChain(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListFeedback(ctx)
	if err != nil || len(rows) != 30 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
}
