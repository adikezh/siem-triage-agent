package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/adikezh/siem-triage-agent/internal/config"
	"github.com/adikezh/siem-triage-agent/internal/enrich"
	"github.com/adikezh/siem-triage-agent/internal/ingest"
	"github.com/adikezh/siem-triage-agent/internal/store"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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

func TestGroupingOverride(t *testing.T) {
	b := time.Now().UTC()
	a := []Alert{
		{Timestamp: b, RuleID: "r1", RuleLevel: 8, Groups: []string{"authentication_failed"}, Agent: map[string]any{"id": "a1"}, SrcIP: "1.2.3.4"},
		{Timestamp: b.Add(5 * time.Minute), RuleID: "r2", RuleLevel: 8, Groups: []string{"authentication_failed"}, Agent: map[string]any{"id": "a1"}, SrcIP: "1.2.3.4"},
	}
	cfg := config.Grouping{Default: []string{"rule.id", "agent.id", "src_ip"}, Overrides: []config.GroupingOverride{{Match: config.GroupingMatch{Groups: []string{"authentication_failed"}}, Key: []string{"agent.id", "src_ip"}}}}
	incidents := groupWithWindowConfig(a, 15*time.Minute, 6*time.Hour, cfg)
	if len(incidents) != 1 || incidents[0].AlertCount != 2 || incidents[0].Fingerprint != "a1|1.2.3.4" {
		t.Fatalf("got %#v", incidents)
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

func TestSlackSignatureAuth(t *testing.T) {
	body := `{"actions":[{"action_id":"open","value":"inc-1"}]}`
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte("signing-secret"))
	_, _ = mac.Write([]byte("v0:" + ts + ":" + body))
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("X-Slack-Request-Timestamp", ts)
	r.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
	w := httptest.NewRecorder()
	slackSignatureAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), "signing-secret").ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("valid signature status=%d", w.Code)
	}
	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("X-Slack-Request-Timestamp", ts)
	r.Header.Set("X-Slack-Signature", "v0=bad")
	w = httptest.NewRecorder()
	slackSignatureAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), "signing-secret").ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("invalid signature status=%d", w.Code)
	}
}

func TestPollWazuhPersistsAlertAndIncident(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"hits":{"hits":[{"_id":"live-1","_source":{"@timestamp":"2026-09-23T08:00:00Z","rule":{"id":"100","level":8,"description":"test","groups":["authentication_failed"]},"agent":{"id":"a1"},"data":{"srcip":"203.0.113.8"}},"sort":["2026-09-23T08:00:00Z","live-1"]}]}}`))
	}))
	defer srv.Close()
	db, err := store.Open(filepath.Join(t.TempDir(), "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pollWazuh(ctx, db, ingest.WazuhClient{BaseURL: srv.URL, Index: "alerts-*"}, time.Hour, 15*time.Minute, 6*time.Hour, config.Grouping{Default: []string{"rule.id", "agent.id", "src_ip"}}, map[string]enrich.Asset{"203.0.113.8": {IP: "203.0.113.8", Criticality: 5}}, enrich.IOC{IPs: map[string]bool{"203.0.113.8": true}}, nil, "")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rows, e := db.ListIncidents(ctx)
		if e == nil && len(rows) == 1 && rows[0].Score == 80 && rows[0].Severity == "critical" {
			cancel()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	rows, _ := db.ListIncidents(ctx)
	t.Fatalf("poller did not persist expected incident: %#v", rows)
}

func TestScenarioFixtures(t *testing.T) {
	cases := []struct {
		name                string
		incidents, minScore int
		severity            string
	}{{"brute_force", 1, 50, "medium"}, {"lateral", 2, 60, "high"}, {"fim_noise", 1, 15, "low"}}
	for _, tc := range cases {
		f, err := os.Open(filepath.Join("testdata", "scenarios", tc.name+".ndjson"))
		if err != nil {
			t.Fatal(err)
		}
		var alerts []Alert
		scan := bufio.NewScanner(f)
		for scan.Scan() {
			var a Alert
			if err := json.Unmarshal(scan.Bytes(), &a); err != nil {
				t.Fatal(err)
			}
			alerts = append(alerts, a)
		}
		_ = f.Close()
		if err := scan.Err(); err != nil {
			t.Fatal(err)
		}
		inc := groupWithWindow(alerts, 15*time.Minute, 6*time.Hour)
		if len(inc) != tc.incidents {
			t.Fatalf("%s incidents=%d want=%d", tc.name, len(inc), tc.incidents)
		}
		for _, got := range inc {
			if got.Score < tc.minScore || got.Severity != tc.severity {
				t.Fatalf("%s got score=%d severity=%s", tc.name, got.Score, got.Severity)
			}
		}
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
