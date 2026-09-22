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

	"github.com/adikezh/siem-triage-agent/internal/auth"
	"github.com/adikezh/siem-triage-agent/internal/config"
	"github.com/adikezh/siem-triage-agent/internal/metrics"
	"github.com/adikezh/siem-triage-agent/internal/report"
	"github.com/adikezh/siem-triage-agent/internal/rules"
	"github.com/adikezh/siem-triage-agent/internal/store"
	triageengine "github.com/adikezh/siem-triage-agent/internal/triage"
	"github.com/adikezh/siem-triage-agent/internal/triage/llm"
	"github.com/adikezh/siem-triage-agent/internal/triage/scoring"
	"github.com/adikezh/siem-triage-agent/internal/web"
)

type Alert struct {
	ID               string         `json:"id"`
	Timestamp        time.Time      `json:"timestamp"`
	RuleID           string         `json:"rule_id"`
	RuleLevel        int            `json:"rule_level"`
	Agent            map[string]any `json:"agent"`
	SrcIP            string         `json:"src_ip"`
	Groups           []string       `json:"groups"`
	RuleDesc         string         `json:"rule_description"`
	Tag              string         `json:"tag,omitempty"`
	Malicious        bool           `json:"threat_intel_malicious,omitempty"`
	Internal         bool           `json:"internal_src,omitempty"`
	Criticality      int            `json:"asset_criticality,omitempty"`
	HighImpactTactic bool           `json:"high_impact_tactic,omitempty"`
}
type Incident struct {
	Fingerprint      string    `json:"fingerprint"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	AlertCount       int       `json:"alert_count"`
	Score            int       `json:"score"`
	Severity         string    `json:"severity"`
	Tags             []string  `json:"tags,omitempty"`
	RuleLevel        int       `json:"rule_level"`
	Malicious        bool      `json:"malicious,omitempty"`
	Internal         bool      `json:"internal_whitelist,omitempty"`
	Criticality      int       `json:"criticality,omitempty"`
	HighImpactTactic bool      `json:"high_impact_tactic,omitempty"`
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
	case "report":
		reportCommand(os.Args[2:])
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
	llmURL := fs.String("llm-url", "", "optional OpenAI-compatible base URL")
	llmModel := fs.String("llm-model", "", "optional LLM model")
	llmKeyEnv := fs.String("llm-api-key-env", "", "environment variable containing LLM API key")
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
	var engine *triageengine.Engine
	if *llmURL != "" {
		key := ""
		if *llmKeyEnv != "" {
			key = os.Getenv(*llmKeyEnv)
		}
		p := llm.OpenAICompatible{BaseURL: *llmURL, APIKey: key}
		engine = &triageengine.Engine{Threshold: cfg.Triage.LLMThreshold, Provider: p, Model: *llmModel, InternalCIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"}}
	}
	for _, i := range inc {
		if engine != nil {
			tr := engine.Analyze(context.Background(), triageengine.Case{Rule: scoring.Input{RuleLevel: i.RuleLevel, Malicious: i.Malicious, Criticality: i.Criticality, HighImpactTactic: i.HighImpactTactic, InternalWhitelist: i.Internal}, RuleSeverity: i.Severity, Prompt: llm.PromptInput{Rule: i.Fingerprint, Description: "correlated SIEM incident", SourceIP: strings.Split(i.Fingerprint, "|")[2]}})
			i.Score = tr.Score
			i.Severity = tr.Severity
			_ = db.SaveLLMTrace(context.Background(), store.LLMTrace{IncidentID: i.Fingerprint, Provider: tr.Trace.Provider, Model: tr.Trace.Model, PromptHash: tr.Trace.PromptHash, LatencyMS: tr.Trace.LatencyMS, Used: tr.Trace.Used, Error: tr.Trace.Error})
		}
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
			s := scoring.Score(scoring.Input{RuleLevel: a.RuleLevel, Malicious: a.Malicious, Criticality: a.Criticality, HighImpactTactic: a.HighImpactTactic, InternalWhitelist: a.Internal})
			inc := Incident{Fingerprint: fp, FirstSeen: a.Timestamp, LastSeen: a.Timestamp, AlertCount: 1, RuleLevel: a.RuleLevel, Malicious: a.Malicious, Internal: a.Internal, Criticality: a.Criticality, HighImpactTactic: a.HighImpactTactic, Score: s, Severity: scoring.Severity(s)}
			if a.Tag != "" {
				inc.Tags = []string{a.Tag}
			}
			out = append(out, inc)
			m[fp] = len(out) - 1
		} else {
			out[i].LastSeen = a.Timestamp
			out[i].AlertCount++
			if a.RuleLevel > out[i].RuleLevel {
				out[i].RuleLevel = a.RuleLevel
			}
			if a.Malicious {
				out[i].Malicious = true
			}
			if a.Internal {
				out[i].Internal = true
			}
			if a.Criticality > out[i].Criticality {
				out[i].Criticality = a.Criticality
			}
			if a.HighImpactTactic {
				out[i].HighImpactTactic = true
			}
			s := scoring.Score(scoring.Input{RuleLevel: out[i].RuleLevel, Malicious: out[i].Malicious, Criticality: out[i].Criticality, HighImpactTactic: out[i].HighImpactTactic, InternalWhitelist: out[i].Internal})
			out[i].Score = s
			out[i].Severity = scoring.Severity(s)
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
	return scoring.Score(scoring.Input{RuleLevel: level})
}
func severity(s int) string {
	return scoring.Severity(s)
}
func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("listen", ":8080", "address")
	dbPath := fs.String("db", "data/triage.db", "SQLite database path")
	configPath := fs.String("config", "", "YAML configuration path")
	apiKeyEnv := fs.String("api-key-env", "", "environment variable containing API key")
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
	apiKey := ""
	if *apiKeyEnv != "" {
		apiKey, err = auth.RequireKey(os.Getenv(*apiKeyEnv))
		if err != nil {
			panic(err)
		}
	}
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	http.Handle("/metrics", metrics.Handler(db))
	http.Handle("/", web.Handler(db))
	incidentsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	http.Handle("/api/incidents", auth.MiddlewareHash(incidentsHandler, auth.HashKey(apiKey)))
	http.Handle("/api/incidents/", auth.MiddlewareHash(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/incidents/")
		rec, e := db.GetIncident(r.Context(), id)
		if e != nil {
			http.Error(w, "incident not found", http.StatusNotFound)
			return
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(rec)
	}), auth.HashKey(apiKey)))
	http.Handle("/api/stats", auth.MiddlewareHash(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rows, e := db.ListIncidents(r.Context())
		if e != nil {
			http.Error(w, "storage error", 500)
			return
		}
		counts := map[string]int{}
		for _, x := range rows {
			counts[x.Severity]++
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"total": len(rows), "by_severity": counts})
	}), auth.HashKey(apiKey)))
	feedbackHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	http.Handle("/api/incidents/feedback", auth.MiddlewareHash(feedbackHandler, auth.HashKey(apiKey)))
	fmt.Println("listening on", *addr)
	if e := http.ListenAndServe(*addr, nil); e != nil {
		panic(e)
	}
}
func usage() {
	fmt.Println("triage run --file alerts.ndjson [--out report.json]\ntriage serve [--listen :8080]\ntriage report --db data/triage.db --period 7d --out weekly.md\ntriage version")
}

func reportCommand(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	dbPath := fs.String("db", "data/triage.db", "SQLite database path")
	period := fs.String("period", "7d", "period: 24h, 7d, 30d")
	out := fs.String("out", "", "output markdown path")
	format := fs.String("format", "md", "format (md only)")
	fs.Parse(args)
	if *format != "md" {
		fmt.Fprintln(os.Stderr, "only --format md is currently supported")
		os.Exit(2)
	}
	d, e := time.ParseDuration(*period)
	if e != nil {
		if strings.HasSuffix(*period, "d") {
			d0, e0 := time.ParseDuration(strings.TrimSuffix(*period, "d") + "h")
			if e0 != nil {
				panic(e0)
			}
			d = d0 * 24
		} else {
			panic(e)
		}
	}
	db, e := store.Open(*dbPath)
	if e != nil {
		panic(e)
	}
	defer db.Close()
	text, e := report.Markdown(context.Background(), db, d)
	if e != nil {
		panic(e)
	}
	if *out != "" {
		if e = os.WriteFile(*out, []byte(text), 0600); e != nil {
			panic(e)
		}
	} else {
		fmt.Print(text)
	}
}
