package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adikezh/siem-triage-agent/internal/config"
	"github.com/adikezh/siem-triage-agent/internal/rules"
	"github.com/adikezh/siem-triage-agent/internal/store"
)

type Alert struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	RuleID    string         `json:"rule_id"`
	RuleLevel int            `json:"rule_level"`
	Agent     map[string]any `json:"agent"`
	SrcIP     string         `json:"src_ip"`
	Groups    []string       `json:"groups"`
	RuleDesc  string         `json:"rule_description"`
	Tag       string         `json:"tag,omitempty"`
}
type Incident struct {
	Fingerprint string    `json:"fingerprint"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	AlertCount  int       `json:"alert_count"`
	Score       int       `json:"score"`
	Severity    string    `json:"severity"`
	Tags        []string  `json:"tags,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "version":
		fmt.Println("triage dev")
	case "run":
		run(os.Args[2:])
	case "serve":
		serve(os.Args[2:])
	default:
		usage()
	}
}
func run(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	file := fs.String("file", "", "NDJSON input")
	out := fs.String("out", "", "JSON output")
	dbPath := fs.String("db", "data/triage.db", "SQLite database path")
	configPath := fs.String("config", "", "YAML configuration path")
	fs.Parse(args)
	cfg, err := config.Load(*configPath)
	if err != nil {
		panic(err)
	}
	if *configPath != "" && *dbPath == "data/triage.db" {
		*dbPath = cfg.Storage.Path
	}
	if *file == "" {
		fmt.Fprintln(os.Stderr, "--file is required")
		os.Exit(2)
	}
	f, e := os.Open(*file)
	if e != nil {
		panic(e)
	}
	defer f.Close()
	var alerts []Alert
	seen := map[string]bool{}
	var suppressions []rules.Suppression
	if cfg.Correlation.SuppressionsFile != "" {
		suppressions, err = rules.Load(cfg.Correlation.SuppressionsFile)
		if err != nil {
			panic(err)
		}
	}
	s := bufio.NewScanner(f)
	for s.Scan() {
		var a Alert
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}
		if e = json.Unmarshal([]byte(s.Text()), &a); e != nil {
			panic(e)
		}
		if seen[a.ID] {
			continue
		}
		seen[a.ID] = true
		if len(suppressions) > 0 {
			agentID, _ := a.Agent["id"].(string)
			d := rules.Evaluate(rules.Alert{RuleID: a.RuleID, RuleDesc: a.RuleDesc, SrcIP: a.SrcIP, Groups: a.Groups, AgentID: agentID}, suppressions, time.Now().UTC())
			if d.Suppressed {
				continue
			}
			if d.Downgrade && a.RuleLevel > 3 {
				a.RuleLevel = 3
			}
			a.Tag = d.Tag
		}
		alerts = append(alerts, a)
	}
	sortAlerts(alerts)
	inc := groupWithWindow(alerts, cfg.Correlation.Window, cfg.Correlation.MaxIncidentAge)
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0700); err != nil {
		panic(err)
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	for _, i := range inc {
		if err := db.SaveIncident(context.Background(), i, i.Fingerprint+"/"+i.FirstSeen.Format(time.RFC3339Nano), i.Fingerprint, i.Severity, i.Score, i.AlertCount, i.FirstSeen, i.LastSeen); err != nil {
			panic(err)
		}
	}
	b, _ := json.MarshalIndent(inc, "", "  ")
	if *out != "" {
		if e = os.WriteFile(*out, b, 0600); e != nil {
			panic(e)
		}
	} else {
		fmt.Println(string(b))
	}
}
func sortAlerts(a []Alert) {
	for i := range a {
		for j := i + 1; j < len(a); j++ {
			if a[j].Timestamp.Before(a[i].Timestamp) {
				a[i], a[j] = a[j], a[i]
			}
		}
	}
}
func group(as []Alert) []Incident {
	return groupWithWindow(as, 15*time.Minute, 6*time.Hour)
}
func groupWithWindow(as []Alert, window, maxAge time.Duration) []Incident {
	m := map[string]int{}
	var out []Incident
	for _, a := range as {
		agent, _ := a.Agent["id"].(string)
		fp := a.RuleID + "|" + agent + "|" + a.SrcIP
		i, ok := m[fp]
		if !ok || a.Timestamp.Sub(out[i].LastSeen) > window || a.Timestamp.Sub(out[i].FirstSeen) > maxAge {
			inc := Incident{Fingerprint: fp, FirstSeen: a.Timestamp, LastSeen: a.Timestamp, AlertCount: 1, Score: score(a.RuleLevel), Severity: severity(score(a.RuleLevel))}
			if a.Tag != "" {
				inc.Tags = []string{a.Tag}
			}
			out = append(out, inc)
			m[fp] = len(out) - 1
		} else {
			out[i].LastSeen = a.Timestamp
			out[i].AlertCount++
			if a.Tag != "" {
				found := false
				for _, tag := range out[i].Tags {
					if tag == a.Tag {
						found = true
					}
				}
				if !found {
					out[i].Tags = append(out[i].Tags, a.Tag)
				}
			}
		}
	}
	return out
}
func score(level int) int {
	s := level * 5
	if s > 100 {
		return 100
	}
	return s
}
func severity(s int) string {
	if s >= 80 {
		return "critical"
	}
	if s >= 60 {
		return "high"
	}
	if s >= 40 {
		return "medium"
	}
	return "low"
}
func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("listen", ":8080", "address")
	dbPath := fs.String("db", "data/triage.db", "SQLite database path")
	configPath := fs.String("config", "", "YAML configuration path")
	fs.Parse(args)
	cfg, err := config.Load(*configPath)
	if err != nil {
		panic(err)
	}
	if *configPath != "" && *dbPath == "data/triage.db" {
		*dbPath = cfg.Storage.Path
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	http.HandleFunc("/api/incidents", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		records, e := db.ListIncidents(r.Context())
		if e != nil {
			http.Error(w, "storage error", 500)
			return
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(records)
	})
	http.HandleFunc("/api/incidents/feedback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var input struct {
			IncidentID string `json:"incident_id"`
			Verdict    string `json:"verdict"`
			Comment    string `json:"comment"`
			Actor      string `json:"actor"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.IncidentID == "" {
			http.Error(w, "invalid JSON: incident_id is required", http.StatusBadRequest)
			return
		}
		if input.Verdict != "tp" && input.Verdict != "fp" && input.Verdict != "ack" {
			http.Error(w, "verdict must be tp, fp or ack", http.StatusBadRequest)
			return
		}
		if err := db.AddFeedback(r.Context(), input.IncidentID, input.Verdict, input.Comment, input.Actor); err != nil {
			http.Error(w, "could not save feedback", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"saved"}`))
	})
	fmt.Println("listening on", *addr)
	if e := http.ListenAndServe(*addr, nil); e != nil {
		panic(e)
	}
}
func usage() {
	fmt.Println("triage run --file alerts.ndjson [--out report.json]\ntriage serve [--listen :8080]\ntriage version")
}
