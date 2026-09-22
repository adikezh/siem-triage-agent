package main

import (
	"context"
	"fmt"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGroupWindow(t *testing.T) {
	b := time.Now().UTC()
	a := []Alert{{ID: "1", Timestamp: b, RuleID: "r", RuleLevel: 10, Agent: map[string]any{"id": "a"}, SrcIP: "1.2.3.4"}, {ID: "2", Timestamp: b.Add(10 * time.Minute), RuleID: "r", RuleLevel: 10, Agent: map[string]any{"id": "a"}, SrcIP: "1.2.3.4"}, {ID: "3", Timestamp: b.Add(30 * time.Minute), RuleID: "r", RuleLevel: 10, Agent: map[string]any{"id": "a"}, SrcIP: "1.2.3.4"}}
	x := group(a)
	if len(x) != 2 || x[0].AlertCount != 2 {
		t.Fatalf("got %#v", x)
	}
}

func TestWebhookFeedbackCallbacks(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "triage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	if err = db.SaveIncident(context.Background(), map[string]string{"severity": "high"}, "inc-1", "r|a|ip", "high", 80, 1, now, now); err != nil {
		t.Fatal(err)
	}
	h := callbackAuth(webhookHandler(db, "telegram"), "secret")
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"callback_query":{"data":"fp|inc-1","from":{"username":"alice"}}}`))
	req.Header.Set("X-Telegram-Bot-Api-Secret-Token", "secret")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	rows, err := db.ListFeedback(context.Background())
	if err != nil || len(rows) != 1 || rows[0].Verdict != "fp" || rows[0].Actor != "alice" {
		t.Fatalf("feedback=%#v err=%v", rows, err)
	}
}

func BenchmarkGroup100K(b *testing.B) {
	alerts := make([]Alert, 100000)
	base := time.Now().UTC()
	for i := range alerts {
		alerts[i] = Alert{ID: fmt.Sprint(i), Timestamp: base.Add(time.Duration(i) * time.Second), RuleID: "r", Agent: map[string]any{"id": "a"}, SrcIP: "1.2.3.4", RuleLevel: 5}
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = group(alerts)
	}
}
