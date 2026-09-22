package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/adikezh/siem-triage-agent/internal/auth"
	"github.com/adikezh/siem-triage-agent/internal/config"
	"github.com/adikezh/siem-triage-agent/internal/enrich"
	"github.com/adikezh/siem-triage-agent/internal/eval"
	"github.com/adikezh/siem-triage-agent/internal/httpapi"
	"github.com/adikezh/siem-triage-agent/internal/ingest"
	"github.com/adikezh/siem-triage-agent/internal/metrics"
	"github.com/adikezh/siem-triage-agent/internal/notify"
	"github.com/adikezh/siem-triage-agent/internal/pipeline"
	"github.com/adikezh/siem-triage-agent/internal/report"
	"github.com/adikezh/siem-triage-agent/internal/rules"
	"github.com/adikezh/siem-triage-agent/internal/store"
	triageengine "github.com/adikezh/siem-triage-agent/internal/triage"
	"github.com/adikezh/siem-triage-agent/internal/triage/llm"
	"github.com/adikezh/siem-triage-agent/internal/triage/scoring"
	"github.com/adikezh/siem-triage-agent/internal/web"
	"gopkg.in/yaml.v3"
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
	Summary          string    `json:"summary,omitempty"`
	Actions          []string  `json:"actions,omitempty"`
	FPProbability    float64   `json:"fp_probability,omitempty"`
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
	case "demo":
		demoCommand(os.Args[2:])
	case "report":
		reportCommand(os.Args[2:])
	case "feedback":
		if len(os.Args) > 2 && os.Args[2] == "export" {
			feedbackExport(os.Args[3:])
		} else {
			usage()
		}
	case "apikey":
		if len(os.Args) > 2 && os.Args[2] == "create" {
			apiKeyCreate(os.Args[3:])
		} else if len(os.Args) > 2 && os.Args[2] == "list" {
			apiKeyList(os.Args[3:])
		} else if len(os.Args) > 2 && os.Args[2] == "revoke" {
			apiKeyRevoke(os.Args[3:])
		} else if len(os.Args) > 2 && os.Args[2] == "rotate" {
			apiKeyRotate(os.Args[3:])
		} else {
			usage()
		}
	case "rules":
		if len(os.Args) > 2 && os.Args[2] == "test" {
			rulesTest(os.Args[3:])
		} else {
			usage()
		}
	case "eval":
		evalCommand(os.Args[2:])
	case "assets":
		if len(os.Args) > 2 && os.Args[2] == "import" {
			assetsImport(os.Args[3:])
		} else {
			usage()
		}
	case "migrate":
		if len(os.Args) > 2 && os.Args[2] == "up" {
			migrateUp(os.Args[3:])
		} else {
			usage()
		}
	default:
		usage()
	}
}

func rulesTest(args []string) {
	fs := flag.NewFlagSet("rules test", flag.ExitOnError)
	file := fs.String("file", "", "NDJSON input")
	configPath := fs.String("config", "", "YAML configuration path")
	fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "--file is required")
		os.Exit(2)
	}
	cfg, e := config.Load(*configPath)
	if e != nil {
		panic(e)
	}
	f, e := os.Open(*file)
	if e != nil {
		panic(e)
	}
	defer f.Close()
	ss, e := rules.Load(cfg.Correlation.SuppressionsFile)
	if e != nil {
		panic(e)
	}
	s := bufio.NewScanner(f)
	input, suppressed := 0, 0
	for s.Scan() {
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}
		input++
		var a Alert
		if e = json.Unmarshal([]byte(s.Text()), &a); e != nil {
			panic(e)
		}
		a.Internal = enrich.IsInternal(a.SrcIP, cfg.Enrichment.InternalCIDRs)
		agentID, _ := a.Agent["id"].(string)
		d := rules.Evaluate(rules.Alert{RuleID: a.RuleID, RuleDesc: a.RuleDesc, SrcIP: a.SrcIP, Groups: a.Groups, AgentID: agentID}, ss, time.Now().UTC())
		if d.Suppressed {
			suppressed++
		}
	}
	if e = s.Err(); e != nil {
		panic(e)
	}
	b, _ := json.MarshalIndent(map[string]int{"input": input, "suppressed": suppressed, "accepted": input - suppressed}, "", "  ")
	fmt.Println(string(b))
}

func assetsImport(args []string) {
	fs := flag.NewFlagSet("assets import", flag.ExitOnError)
	file := fs.String("file", "", "CSV or YAML asset inventory")
	out := fs.String("out", "", "output YAML path (optional)")
	fs.Parse(args)
	if *file == "" {
		fmt.Fprintln(os.Stderr, "--file is required")
		os.Exit(2)
	}
	var assets map[string]enrich.Asset
	var err error
	if strings.HasSuffix(strings.ToLower(*file), ".csv") {
		assets, err = enrich.LoadCSV(*file)
	} else {
		assets, err = enrich.Load(*file)
	}
	if err != nil {
		panic(err)
	}
	list := make([]enrich.Asset, 0, len(assets))
	for _, asset := range assets {
		list = append(list, asset)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].IP < list[j].IP })
	payload, err := yaml.Marshal(enrich.File{Assets: list})
	if err != nil {
		panic(err)
	}
	if *out == "" {
		fmt.Print(string(payload))
		return
	}
	if err := os.WriteFile(*out, payload, 0600); err != nil {
		panic(err)
	}
	fmt.Printf("imported %d assets to %s\n", len(list), *out)
}

func migrateUp(args []string) {
	fs := flag.NewFlagSet("migrate up", flag.ExitOnError)
	dbPath := fs.String("db", "data/triage.db", "SQLite database path")
	fs.Parse(args)
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0700); err != nil {
		panic(err)
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		panic(err)
	}
	if err := db.Close(); err != nil {
		panic(err)
	}
	fmt.Printf("database schema is ready: %s\n", *dbPath)
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
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0700); err != nil {
		panic(err)
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	var alerts []Alert
	seen := map[string]bool{}
	var assets map[string]enrich.Asset
	var assetErr error
	if strings.HasSuffix(strings.ToLower(cfg.Enrichment.AssetsFile), ".csv") {
		assets, assetErr = enrich.LoadCSV(cfg.Enrichment.AssetsFile)
	} else {
		assets, assetErr = enrich.Load(cfg.Enrichment.AssetsFile)
	}
	e = assetErr
	if e != nil {
		panic(e)
	}
	iocs, e := enrich.LoadIOC(cfg.Enrichment.IOCFile)
	if e != nil {
		panic(e)
	}
	var threat enrich.ThreatChain
	if key := os.Getenv(cfg.Enrichment.AbuseIPDB.APIKeyEnv); key != "" {
		threat = append(threat, enrich.AbuseIPDB{BaseURL: cfg.Enrichment.AbuseIPDB.BaseURL, APIKey: key})
	}
	if key := os.Getenv(cfg.Enrichment.VirusTotal.APIKeyEnv); key != "" {
		threat = append(threat, enrich.VirusTotal{BaseURL: cfg.Enrichment.VirusTotal.BaseURL, APIKey: key})
	}
	threatCache := enrich.NewThreatCache(24 * time.Hour)
	geoip, geoErr := enrich.OpenGeoIP(cfg.Enrichment.GeoIPFile)
	if geoErr != nil {
		panic(geoErr)
	}
	defer geoip.Close()
	var suppressions []rules.Suppression
	if cfg.Correlation.SuppressionsFile != "" {
		suppressions, err = rules.Load(cfg.Correlation.SuppressionsFile)
		if err != nil {
			panic(err)
		}
	}
	rows, e := db.ListSuppressions(context.Background())
	if e != nil {
		panic(e)
	}
	for _, row := range rows {
		var expires *time.Time
		if row.ExpiresAt != "" {
			t, parseErr := time.Parse(time.RFC3339Nano, row.ExpiresAt)
			if parseErr != nil {
				continue
			}
			expires = &t
		}
		suppressions = append(suppressions, rules.Suppression{Match: rules.Match{Fingerprint: row.Fingerprint}, Action: row.Action, Reason: row.Reason, CreatedBy: row.CreatedBy, ExpiresAt: expires})
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
			d := rules.Evaluate(rules.Alert{RuleID: a.RuleID, RuleDesc: a.RuleDesc, SrcIP: a.SrcIP, Groups: a.Groups, AgentID: agentID, Fingerprint: a.RuleID + "|" + agentID + "|" + a.SrcIP}, suppressions, time.Now().UTC())
			if d.Suppressed {
				continue
			}
			if d.Downgrade && a.RuleLevel > 3 {
				a.RuleLevel = 3
			}
			a.Tag = d.Tag
		}
		if asset, ok := enrich.Apply(assets, a.SrcIP); ok {
			a.Criticality = asset.Criticality
		}
		if iocs.MaliciousIP(a.SrcIP) {
			a.Malicious = true
		}
		if len(threat) > 0 && a.SrcIP != "" {
			cached, found, cacheErr := db.LoadThreatCache(context.Background(), a.SrcIP, time.Now().UTC())
			if cacheErr == nil && found {
				if cached.Malicious {
					a.Malicious = true
				}
			} else {
				lookupCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				result, lookupErr := threatCache.Lookup(lookupCtx, a.SrcIP, threat)
				cancel()
				if lookupErr == nil {
					if result.Malicious {
						a.Malicious = true
					}
					_ = db.SaveThreatCache(context.Background(), store.ThreatCacheRecord{IP: a.SrcIP, Source: result.Source, Details: result.Details, Malicious: result.Malicious}, 24*time.Hour)
				}
			}
		}
		alerts = append(alerts, a)
	}
	sortAlerts(alerts)
	inc := groupWithWindowConfig(alerts, cfg.Correlation.Window, cfg.Correlation.MaxIncidentAge, cfg.Correlation.Grouping)
	for _, a := range alerts {
		if e := db.SaveAlert(context.Background(), a.ID, "file", a.Timestamp, a); e != nil {
			panic(e)
		}
	}
	var engine *triageengine.Engine
	if *llmURL != "" {
		key := ""
		if *llmKeyEnv != "" {
			key = os.Getenv(*llmKeyEnv)
		}
		p := llm.OpenAICompatible{BaseURL: *llmURL, APIKey: key}
		engine = &triageengine.Engine{Threshold: cfg.Triage.LLMThreshold, Provider: p, Model: *llmModel, InternalCIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"}}
	} else if len(cfg.Triage.Providers) > 0 && cfg.Triage.Mode != "rule-only" {
		providers := make([]llm.Provider, 0, len(cfg.Triage.Providers))
		model := cfg.Triage.Providers[0].Model
		for _, p := range cfg.Triage.Providers {
			key := os.Getenv(p.APIKeyEnv)
			var provider llm.Provider
			switch strings.ToLower(p.Type) {
			case "openai_compatible", "openai-compatible":
				provider = llm.OpenAICompatible{BaseURL: p.BaseURL, APIKey: key}
			case "ollama":
				provider = llm.Ollama{BaseURL: p.BaseURL}
			case "anthropic":
				provider = llm.Anthropic{BaseURL: p.BaseURL, APIKey: key}
			default:
				panic("unsupported configured LLM provider: " + p.Type)
			}
			providers = append(providers, provider)
		}
		budget := &llm.Budget{CallsPerHour: cfg.Triage.Budget.CallsPerHour, USDPerDay: cfg.Triage.Budget.USDPerDay, CostPerCall: cfg.Triage.Budget.CostPerCall}
		engine = &triageengine.Engine{Threshold: cfg.Triage.LLMThreshold, Provider: llm.ChainProvider{Chain: llm.Chain{Providers: providers, Budget: budget}}, Model: model, InternalCIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"}}
	}
	for _, i := range inc {
		fpCount, hasTP, e := db.FingerprintStats(context.Background(), i.Fingerprint, time.Now().UTC().Add(-30*24*time.Hour))
		if e != nil {
			panic(e)
		}
		if fpCount >= 20 && !hasTP {
			s := scoring.Score(scoring.Input{RuleLevel: i.RuleLevel, Malicious: i.Malicious, Criticality: i.Criticality, HighImpactTactic: i.HighImpactTactic, InternalWhitelist: i.Internal, FrequentFalsePositive: true})
			i.Score = s
			i.Severity = scoring.Severity(s)
		}
		if engine != nil {
			historyRows, historyErr := db.IncidentHistory(context.Background(), i.Fingerprint, 5)
			if historyErr != nil {
				panic(historyErr)
			}
			historyParts := make([]string, 0, len(historyRows))
			historyParts = append(historyParts, fmt.Sprintf("fingerprint_seen_30d=%d; fingerprint_has_tp=%t", fpCount, hasTP))
			for _, h := range historyRows {
				historyParts = append(historyParts, h.LastSeen+":"+h.Severity+":"+h.Verdict)
			}
			sourceIP := ""
			parts := strings.Split(i.Fingerprint, "|")
			if len(parts) >= 3 {
				sourceIP = parts[2]
			}
			geo := ""
			if geoip != nil {
				if country, geoLookupErr := geoip.Lookup(sourceIP); geoLookupErr == nil {
					geo = country
				}
			}
			tr := engine.Analyze(context.Background(), triageengine.Case{Rule: scoring.Input{RuleLevel: i.RuleLevel, Malicious: i.Malicious, Criticality: i.Criticality, HighImpactTactic: i.HighImpactTactic, InternalWhitelist: i.Internal}, RuleSeverity: i.Severity, Prompt: llm.PromptInput{Rule: i.Fingerprint, Description: "correlated SIEM incident", SourceIP: sourceIP, Geo: geo, History: strings.Join(historyParts, "; ")}})
			i.Score = tr.Score
			i.Severity = tr.Severity
			_ = db.SaveLLMTrace(context.Background(), store.LLMTrace{IncidentID: i.Fingerprint, Provider: tr.Trace.Provider, Model: tr.Trace.Model, PromptHash: tr.Trace.PromptHash, LatencyMS: tr.Trace.LatencyMS, Used: tr.Trace.Used, Error: tr.Trace.Error})
		}
		if err := db.SaveIncident(context.Background(), i, i.Fingerprint+"/"+i.FirstSeen.Format(time.RFC3339Nano), i.Fingerprint, i.Severity, i.Score, i.AlertCount, i.FirstSeen, i.LastSeen); err != nil {
			panic(err)
		}
	}
	if err := db.Prune(context.Background(), time.Now().UTC().Add(-cfg.Storage.Retention.Alerts), time.Now().UTC().Add(-cfg.Storage.Retention.LLMCalls)); err != nil {
		panic(err)
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
	sort.SliceStable(a, func(i, j int) bool { return a[i].Timestamp.Before(a[j].Timestamp) })
}
func group(as []Alert) []Incident {
	return groupWithWindow(as, 15*time.Minute, 6*time.Hour)
}
func groupWithWindow(as []Alert, window, maxAge time.Duration) []Incident {
	return groupWithWindowConfig(as, window, maxAge, config.Grouping{Default: []string{"rule.id", "agent.id", "src_ip"}})
}
func alertFingerprint(a Alert, grouping config.Grouping) string {
	keys := grouping.Default
	if len(keys) == 0 {
		keys = []string{"rule.id", "agent.id", "src_ip"}
	}
	for _, override := range grouping.Overrides {
		matched := true
		for _, wanted := range override.Match.Groups {
			found := false
			for _, actual := range a.Groups {
				if actual == wanted {
					found = true
					break
				}
			}
			if !found {
				matched = false
				break
			}
		}
		if matched && len(override.Key) > 0 {
			keys = override.Key
			break
		}
	}
	agent, _ := a.Agent["id"].(string)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		switch key {
		case "rule.id", "rule_id":
			values = append(values, a.RuleID)
		case "agent.id", "agent_id":
			values = append(values, agent)
		case "src_ip", "source.ip":
			values = append(values, a.SrcIP)
		default:
			values = append(values, "")
		}
	}
	return strings.Join(values, "|")
}
func groupWithWindowConfig(as []Alert, window, maxAge time.Duration, grouping config.Grouping) []Incident {
	m := map[string]int{}
	var out []Incident
	for _, a := range as {
		fp := alertFingerprint(a, grouping)
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
	apiKeyRole := fs.String("api-key-role", "admin", "role assigned to the environment API key: viewer, analyst or admin")
	webhookSecretEnv := fs.String("webhook-secret-env", "", "environment variable containing Telegram/Slack webhook secret")
	slackSigningSecretEnv := fs.String("slack-signing-secret-env", "", "environment variable containing Slack signing secret")
	sourceURL := fs.String("source-url", "", "optional Wazuh/OpenSearch URL for continuous polling")
	sourceIndex := fs.String("source-index", "wazuh-alerts-*", "source index pattern")
	sourceUser := fs.String("source-user", "", "source basic-auth username")
	sourcePasswordEnv := fs.String("source-password-env", "", "environment variable containing source password")
	sourceInterval := fs.Duration("source-interval", 15*time.Second, "source polling interval")
	webhookURL := fs.String("webhook-url", "", "optional notification webhook URL")
	tlsCert := fs.String("tls-cert", "", "TLS certificate path")
	tlsKey := fs.String("tls-key", "", "TLS private key path")
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
	assets := map[string]enrich.Asset{}
	if cfg.Enrichment.AssetsFile != "" {
		if strings.HasSuffix(strings.ToLower(cfg.Enrichment.AssetsFile), ".csv") {
			assets, err = enrich.LoadCSV(cfg.Enrichment.AssetsFile)
		} else {
			assets, err = enrich.Load(cfg.Enrichment.AssetsFile)
		}
		if err != nil {
			panic(err)
		}
	}
	iocs, err := enrich.LoadIOC(cfg.Enrichment.IOCFile)
	if err != nil {
		panic(err)
	}
	apiKey := ""
	if *apiKeyEnv != "" {
		apiKey, err = auth.RequireKey(os.Getenv(*apiKeyEnv))
		if err != nil {
			panic(err)
		}
	}
	authHash := ""
	if apiKey != "" {
		if *apiKeyRole != "viewer" && *apiKeyRole != "analyst" && *apiKeyRole != "admin" {
			panic("api-key-role must be viewer, analyst or admin")
		}
		authHash = auth.HashKey(apiKey)
	}
	protectRoles := func(next http.Handler, allowed ...string) http.Handler {
		next = httpapi.RateLimit(next, 120, time.Minute)
		if authHash != "" {
			for _, candidate := range allowed {
				if candidate == *apiKeyRole || *apiKeyRole == "admin" {
					return auth.MiddlewareHashRole(next, authHash, *apiKeyRole)
				}
			}
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "forbidden", http.StatusForbidden) })
		}
		hasKeys, hasKeysErr := db.HasAPIKeys(context.Background())
		if hasKeysErr != nil {
			panic(hasKeysErr)
		}
		if !hasKeys {
			return next
		}
		return auth.MiddlewareVerifyRole(next, func(raw string) (string, bool) {
			role, ok, verifyErr := db.VerifyAPIKey(context.Background(), raw)
			if verifyErr != nil || !ok {
				return "", false
			}
			for _, candidate := range allowed {
				if role == candidate || role == "admin" {
					return role, true
				}
			}
			return role, false
		})
	}
	protect := func(next http.Handler) http.Handler { return protectRoles(next, "viewer", "analyst", "admin") }
	webhookSecret := ""
	if *webhookSecretEnv != "" {
		webhookSecret = strings.TrimSpace(os.Getenv(*webhookSecretEnv))
		if webhookSecret == "" {
			panic("webhook secret environment variable is empty")
		}
	}
	slackSigningSecret := ""
	if *slackSigningSecretEnv != "" {
		slackSigningSecret = strings.TrimSpace(os.Getenv(*slackSigningSecretEnv))
		if slackSigningSecret == "" {
			panic("slack signing secret environment variable is empty")
		}
	}
	engine := configuredEngine(cfg)
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	http.Handle("/metrics", metrics.Handler(db))
	http.Handle("/openapi.json", httpapi.OpenAPIHandler())
	http.Handle("/", web.HandlerWithAssets(db, assets))
	incidentsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		q := r.URL.Query()
		severity := q.Get("severity")
		if severity != "" && severity != "low" && severity != "medium" && severity != "high" && severity != "critical" {
			http.Error(w, "invalid severity", http.StatusBadRequest)
			return
		}
		limit := 0
		if raw := q.Get("limit"); raw != "" {
			parsed, parseErr := strconv.Atoi(raw)
			if parseErr != nil || parsed < 1 || parsed > 1000 {
				http.Error(w, "limit must be 1..1000", http.StatusBadRequest)
				return
			}
			limit = parsed
		}
		since := q.Get("since")
		if since != "" {
			if _, parseErr := time.Parse(time.RFC3339, since); parseErr != nil {
				http.Error(w, "since must be RFC3339", http.StatusBadRequest)
				return
			}
		}
		records, e := db.ListIncidentsFiltered(r.Context(), severity, since, limit)
		if e != nil {
			http.Error(w, "storage error", 500)
			return
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(records)
	})
	http.Handle("/api/incidents", protect(incidentsHandler))
	http.Handle("/api/incidents/", protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/incidents/")
		rec, e := db.GetIncident(r.Context(), id)
		if e != nil {
			http.Error(w, "incident not found", http.StatusNotFound)
			return
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(rec)
	})))
	http.Handle("/api/stats", protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	})))
	http.Handle("/api/assets", protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		out := make([]enrich.Asset, 0, len(assets))
		for _, asset := range assets {
			out = append(out, asset)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})))
	http.Handle("/api/suppressions", protectRoles(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			rows, e := db.ListSuppressions(r.Context())
			if e != nil {
				http.Error(w, "storage error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(w).Encode(rows)
		case http.MethodPost:
			var input struct{ Fingerprint, Action, Reason, ExpiresAt, CreatedBy string }
			if e := json.NewDecoder(r.Body).Decode(&input); e != nil || input.Fingerprint == "" || input.Reason == "" {
				http.Error(w, "fingerprint and reason are required", http.StatusBadRequest)
				return
			}
			if input.Action != "drop" && input.Action != "downgrade" && input.Action != "tag" {
				http.Error(w, "action must be drop, downgrade or tag", http.StatusBadRequest)
				return
			}
			if input.ExpiresAt != "" {
				if _, e := time.Parse(time.RFC3339, input.ExpiresAt); e != nil {
					http.Error(w, "expires_at must be RFC3339", http.StatusBadRequest)
					return
				}
			}
			x, e := db.CreateSuppression(r.Context(), input.Fingerprint, input.Action, input.Reason, input.ExpiresAt, input.CreatedBy)
			if e != nil {
				http.Error(w, "could not save suppression", http.StatusInternalServerError)
				return
			}
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(x)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}), "analyst", "admin"))
	http.Handle("/api/suppressions/", protectRoles(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id, e := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/api/suppressions/"), 10, 64)
		if e != nil || id <= 0 {
			http.Error(w, "invalid suppression id", http.StatusBadRequest)
			return
		}
		if e = db.DeleteSuppression(r.Context(), id); e != nil {
			http.Error(w, "could not delete suppression", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}), "admin"))
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
		response := map[string]any{"status": "saved"}
		if input.Verdict == "fp" {
			if incident, incidentErr := db.GetIncident(r.Context(), input.IncidentID); incidentErr == nil {
				if count, countErr := db.FalsePositiveCount(r.Context(), incident.Fingerprint); countErr == nil && count >= 3 {
					response["suppression_suggestion"] = map[string]any{
						"match":      map[string]string{"fingerprint": incident.Fingerprint},
						"action":     "drop",
						"reason":     fmt.Sprintf("fingerprint received %d false-positive verdicts", count),
						"created_by": input.Actor,
					}
				}
			}
		}
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(response)
	})
	http.Handle("/api/incidents/feedback", protectRoles(feedbackHandler, "analyst", "admin"))
	http.Handle("/api/integrations/telegram/callback", callbackAuth(webhookHandler(db, "telegram"), webhookSecret))
	slackCallback := callbackAuth(webhookHandler(db, "slack"), webhookSecret)
	if slackSigningSecret != "" {
		slackCallback = slackSignatureAuth(slackCallback, slackSigningSecret)
	}
	http.Handle("/api/integrations/slack/callback", slackCallback)
	serveCtx, cancelServe := context.WithCancel(context.Background())
	defer cancelServe()
	if *sourceURL != "" {
		if *sourceInterval <= 0 {
			panic("source-interval must be positive")
		}
		password := ""
		if *sourcePasswordEnv != "" {
			password = os.Getenv(*sourcePasswordEnv)
		}
		var sender pipeline.Sender
		if *webhookURL != "" {
			sender = notify.Webhook{URL: *webhookURL, Secret: webhookSecret}
		}
		go pollWazuh(serveCtx, db, ingest.WazuhClient{BaseURL: *sourceURL, Index: *sourceIndex, Username: *sourceUser, Password: password}, *sourceInterval, cfg.Correlation.Window, cfg.Correlation.MaxIncidentAge, cfg.Correlation.Grouping, cfg.Enrichment.InternalCIDRs, assets, iocs, engine, sender, cfg.Correlation.SuppressionsFile)
	}
	fmt.Println("listening on", *addr)
	if (*tlsCert == "") != (*tlsKey == "") {
		panic("tls-cert and tls-key must be provided together")
	}
	server := &http.Server{Addr: *addr}
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(shutdown)
	go func() {
		<-shutdown
		cancelServe()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	var e error
	if *tlsCert != "" {
		e = server.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		e = server.ListenAndServe()
	}
	if e != nil && !errors.Is(e, http.ErrServerClosed) {
		panic(e)
	}
}

func configuredEngine(cfg config.Config) *triageengine.Engine {
	if cfg.Triage.Mode == "rule-only" || len(cfg.Triage.Providers) == 0 {
		return nil
	}
	providers := make([]llm.Provider, 0, len(cfg.Triage.Providers))
	model := cfg.Triage.Providers[0].Model
	for _, p := range cfg.Triage.Providers {
		key := os.Getenv(p.APIKeyEnv)
		var provider llm.Provider
		switch strings.ToLower(p.Type) {
		case "openai_compatible", "openai-compatible":
			provider = llm.OpenAICompatible{BaseURL: p.BaseURL, APIKey: key}
		case "ollama":
			provider = llm.Ollama{BaseURL: p.BaseURL}
		case "anthropic":
			provider = llm.Anthropic{BaseURL: p.BaseURL, APIKey: key}
		default:
			panic("unsupported configured LLM provider: " + p.Type)
		}
		providers = append(providers, provider)
	}
	budget := &llm.Budget{CallsPerHour: cfg.Triage.Budget.CallsPerHour, USDPerDay: cfg.Triage.Budget.USDPerDay, CostPerCall: cfg.Triage.Budget.CostPerCall}
	return &triageengine.Engine{Threshold: cfg.Triage.LLMThreshold, Provider: llm.ChainProvider{Chain: llm.Chain{Providers: providers, Budget: budget}}, Model: model, InternalCIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"}}
}

func pollWazuh(ctx context.Context, db *store.Store, source ingest.WazuhClient, interval, correlationWindow, maxIncidentAge time.Duration, grouping config.Grouping, internalCIDRs []string, assets map[string]enrich.Asset, iocs enrich.IOC, engine *triageengine.Engine, sender pipeline.Sender, suppressionFile string) {
	const sourceName = "wazuh-live"
	saved, err := db.LoadCursor(ctx, sourceName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "source cursor:", err)
		return
	}
	cur := ingest.Cursor{Timestamp: saved.Timestamp}
	if len(saved.SortJSON) > 0 {
		_ = json.Unmarshal(saved.SortJSON, &cur.Sort)
	}
	poll := func() {
		hits, next, err := source.Search(ctx, cur)
		if err != nil {
			fmt.Fprintln(os.Stderr, "source poll:", err)
			return
		}
		suppressions, _ := liveSuppressions(ctx, db, suppressionFile)
		accepted := make([]Alert, 0, len(hits))
		for _, hit := range hits {
			payload := ingest.NormalizeHit(hit)
			var alert Alert
			encoded, _ := json.Marshal(payload)
			if err := json.Unmarshal(encoded, &alert); err == nil {
				alert.Internal = enrich.IsInternal(alert.SrcIP, internalCIDRs)
				agentID, _ := alert.Agent["id"].(string)
				fingerprint := alert.RuleID + "|" + agentID + "|" + alert.SrcIP
				decision := rules.Evaluate(rules.Alert{RuleID: alert.RuleID, RuleDesc: alert.RuleDesc, SrcIP: alert.SrcIP, Groups: alert.Groups, AgentID: agentID, Fingerprint: fingerprint}, suppressions, time.Now().UTC())
				if decision.Suppressed {
					continue
				}
				if decision.Downgrade && alert.RuleLevel > 3 {
					alert.RuleLevel = 3
				}
				alert.Tag = decision.Tag
				adjusted, _ := json.Marshal(alert)
				_ = json.Unmarshal(adjusted, &payload)
			}
			encoded, _ = json.Marshal(payload)
			if err := json.Unmarshal(encoded, &alert); err == nil {
				if asset, ok := enrich.Apply(assets, alert.SrcIP); ok {
					alert.Criticality = asset.Criticality
				}
				alert.Malicious = iocs.MaliciousIP(alert.SrcIP)
				adjusted, _ := json.Marshal(alert)
				_ = json.Unmarshal(adjusted, &payload)
				if err := db.SaveAlert(ctx, hit.ID, "wazuh", hit.Timestamp, payload); err != nil {
					fmt.Fprintln(os.Stderr, "save alert:", err)
					return
				}
				accepted = append(accepted, alert)
			} else if err := db.SaveAlert(ctx, hit.ID, "wazuh", hit.Timestamp, payload); err != nil {
				fmt.Fprintln(os.Stderr, "save alert:", err)
				return
			}
		}
		for _, incident := range groupWithWindowConfig(accepted, correlationWindow, maxIncidentAge, grouping) {
			id := incident.Fingerprint + "/" + incident.FirstSeen.Format(time.RFC3339Nano)
			if previous, lookupErr := db.LatestIncidentByFingerprint(ctx, incident.Fingerprint); lookupErr == nil {
				oldFirst, _ := time.Parse(time.RFC3339Nano, previous.FirstSeen)
				oldLast, _ := time.Parse(time.RFC3339Nano, previous.LastSeen)
				if !oldLast.IsZero() && !incident.FirstSeen.Before(oldLast) && incident.FirstSeen.Sub(oldLast) <= correlationWindow && incident.LastSeen.Sub(oldFirst) <= maxIncidentAge {
					incident.FirstSeen = oldFirst
					incident.AlertCount += previous.AlertCount
					if previous.Score > incident.Score {
						incident.Score = previous.Score
					}
					incident.Severity = scoring.Severity(incident.Score)
					id = previous.ID
				}
			}
			if engine != nil {
				historyRows, historyErr := db.IncidentHistory(ctx, incident.Fingerprint, 5)
				if historyErr != nil {
					fmt.Fprintln(os.Stderr, "incident history:", historyErr)
					return
				}
				historyParts := make([]string, 0, len(historyRows))
				for _, h := range historyRows {
					historyParts = append(historyParts, h.LastSeen+":"+h.Severity+":"+h.Verdict)
				}
				parts := strings.Split(incident.Fingerprint, "|")
				sourceIP := ""
				if len(parts) > 0 {
					sourceIP = parts[len(parts)-1]
				}
				result := engine.Analyze(ctx, triageengine.Case{
					Rule:         scoring.Input{RuleLevel: incident.RuleLevel, Malicious: incident.Malicious, Criticality: incident.Criticality, HighImpactTactic: incident.HighImpactTactic, InternalWhitelist: incident.Internal},
					RuleSeverity: incident.Severity,
					Prompt:       llm.PromptInput{Rule: incident.Fingerprint, Description: "live correlated SIEM incident", SourceIP: sourceIP, History: strings.Join(historyParts, "; ")},
				})
				incident.Score = result.Score
				incident.Severity = result.Severity
				incident.Summary = result.Summary
				incident.Actions = result.Actions
				incident.FPProbability = result.FPProbability
				_ = db.SaveLLMTrace(ctx, store.LLMTrace{IncidentID: id, Provider: result.Trace.Provider, Model: result.Trace.Model, PromptHash: result.Trace.PromptHash, LatencyMS: result.Trace.LatencyMS, Used: result.Trace.Used, Error: result.Trace.Error})
			}
			if err := db.SaveIncident(ctx, incident, id, incident.Fingerprint, incident.Severity, incident.Score, incident.AlertCount, incident.FirstSeen, incident.LastSeen); err != nil {
				fmt.Fprintln(os.Stderr, "save incident:", err)
				return
			}
			if sender != nil {
				payload, _ := json.Marshal(incident)
				_ = db.Enqueue(ctx, id, "webhook", payload)
			}
		}
		if sender != nil {
			_, _ = (pipeline.Dispatcher{Store: db, Sender: sender, BaseDelay: time.Second, MaxAttempts: 10}).Dispatch(ctx, 100)
		}
		b, _ := json.Marshal(next.Sort)
		if err := db.SaveCursor(ctx, sourceName, store.Cursor{Timestamp: next.Timestamp, SortJSON: b}); err != nil {
			fmt.Fprintln(os.Stderr, "save cursor:", err)
			return
		}
		cur = next
	}
	poll()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		}
	}
}

func liveSuppressions(ctx context.Context, db *store.Store, path string) ([]rules.Suppression, error) {
	var out []rules.Suppression
	if path != "" {
		loaded, err := rules.Load(path)
		if err != nil {
			return nil, err
		}
		out = append(out, loaded...)
	}
	rows, err := db.ListSuppressions(ctx)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		var expires *time.Time
		if row.ExpiresAt != "" {
			t, parseErr := time.Parse(time.RFC3339Nano, row.ExpiresAt)
			if parseErr == nil {
				expires = &t
			}
		}
		out = append(out, rules.Suppression{Match: rules.Match{Fingerprint: row.Fingerprint}, Action: row.Action, Reason: row.Reason, CreatedBy: row.CreatedBy, ExpiresAt: expires})
	}
	return out, nil
}

func callbackAuth(next http.Handler, secret string) http.Handler {
	if secret == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get("X-Triage-Webhook-Secret")
		if provided == "" {
			provided = r.Header.Get("X-Telegram-Bot-Api-Secret-Token")
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) != 1 {
			http.Error(w, "invalid webhook secret", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func slackSignatureAuth(next http.Handler, secret string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts := r.Header.Get("X-Slack-Request-Timestamp")
		stamp, err := strconv.ParseInt(ts, 10, 64)
		if err != nil || time.Since(time.Unix(stamp, 0)) > 5*time.Minute || time.Since(time.Unix(stamp, 0)) < -5*time.Minute {
			http.Error(w, "invalid Slack timestamp", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "could not read request", http.StatusBadRequest)
			return
		}
		base := "v0:" + ts + ":" + string(body)
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(base))
		expected := "v0=" + fmt.Sprintf("%x", mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Slack-Signature")), []byte(expected)) != 1 {
			http.Error(w, "invalid Slack signature", http.StatusUnauthorized)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		next.ServeHTTP(w, r)
	})
}

func webhookHandler(db *store.Store, channel string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			CallbackQuery struct {
				Data string `json:"data"`
				From struct {
					ID       int64  `json:"id"`
					Username string `json:"username"`
				} `json:"from"`
			} `json:"callback_query"`
			Actions []struct {
				ActionID string `json:"action_id"`
				Value    string `json:"value"`
			} `json:"actions"`
			User struct {
				ID       string `json:"id"`
				Name     string `json:"name"`
				Username string `json:"username"`
			} `json:"user"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		action, incidentID, actor := "", "", channel
		if payload.CallbackQuery.Data != "" {
			parts := strings.SplitN(payload.CallbackQuery.Data, "|", 2)
			if len(parts) == 2 {
				action, incidentID = parts[0], parts[1]
			}
			if payload.CallbackQuery.From.Username != "" {
				actor = payload.CallbackQuery.From.Username
			} else {
				actor = strconv.FormatInt(payload.CallbackQuery.From.ID, 10)
			}
		} else if len(payload.Actions) > 0 {
			action, incidentID = payload.Actions[0].ActionID, payload.Actions[0].Value
			if payload.User.Username != "" {
				actor = payload.User.Username
			} else if payload.User.Name != "" {
				actor = payload.User.Name
			} else {
				actor = payload.User.ID
			}
		}
		if action == "open" {
			w.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "incident_id": incidentID})
			return
		}
		if action != "tp" && action != "fp" && action != "ack" || incidentID == "" {
			http.Error(w, "callback must contain action and incident id", http.StatusBadRequest)
			return
		}
		if err := db.AddFeedback(r.Context(), incidentID, action, "", actor); err != nil {
			http.Error(w, "could not save feedback", http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "saved", "channel": channel, "incident_id": incidentID, "verdict": action})
	})
}
func usage() {
	fmt.Println("triage run --file alerts.ndjson [--out report.json]\ntriage rules test --file alerts.ndjson --config config.yaml\ntriage feedback export --db data/triage.db --out feedback.jsonl\ntriage eval --dataset feedback.jsonl\ntriage apikey create|list|revoke|rotate --db data/triage.db\ntriage assets import --file inventory.csv --out configs/assets.yaml\ntriage migrate up --db data/triage.db\ntriage demo [--listen :8080 --db data/triage.db]\ntriage serve [--listen :8080]\ntriage report --db data/triage.db --period 7d --out weekly.md\ntriage version")
}

func apiKeyCreate(args []string) {
	fs := flag.NewFlagSet("apikey create", flag.ExitOnError)
	dbPath := fs.String("db", "data/triage.db", "SQLite database path")
	name := fs.String("name", "", "key name")
	role := fs.String("role", "viewer", "viewer, analyst or admin")
	fs.Parse(args)
	if *name == "" || (*role != "viewer" && *role != "analyst" && *role != "admin") {
		fmt.Fprintln(os.Stderr, "--name and valid --role are required")
		os.Exit(2)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0700); err != nil {
		panic(err)
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	x, err := db.CreateAPIKey(context.Background(), *name, *role, raw)
	if err != nil {
		panic(err)
	}
	fmt.Printf("name=%s role=%s key=%s\n", x.Name, x.Role, raw)
}

func apiKeyList(args []string) {
	fs := flag.NewFlagSet("apikey list", flag.ExitOnError)
	dbPath := fs.String("db", "data/triage.db", "SQLite database path")
	fs.Parse(args)
	db, err := store.Open(*dbPath)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	rows, err := db.ListAPIKeys(context.Background())
	if err != nil {
		panic(err)
	}
	b, _ := json.MarshalIndent(rows, "", "  ")
	fmt.Println(string(b))
}

func apiKeyRevoke(args []string) {
	fs := flag.NewFlagSet("apikey revoke", flag.ExitOnError)
	dbPath := fs.String("db", "data/triage.db", "SQLite database path")
	id := fs.Int64("id", 0, "key id")
	fs.Parse(args)
	if *id <= 0 {
		fmt.Fprintln(os.Stderr, "--id is required")
		os.Exit(2)
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	if err = db.RevokeAPIKey(context.Background(), *id); err != nil {
		panic(err)
	}
	fmt.Println("revoked", *id)
}

func apiKeyRotate(args []string) {
	fs := flag.NewFlagSet("apikey rotate", flag.ExitOnError)
	dbPath := fs.String("db", "data/triage.db", "SQLite database path")
	id := fs.Int64("id", 0, "old key id")
	name := fs.String("name", "", "new key name")
	role := fs.String("role", "viewer", "viewer, analyst or admin")
	fs.Parse(args)
	if *id <= 0 || *name == "" || (*role != "viewer" && *role != "analyst" && *role != "admin") {
		fmt.Fprintln(os.Stderr, "--id, --name and valid --role are required")
		os.Exit(2)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	db, err := store.Open(*dbPath)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	if err = db.RevokeAPIKey(context.Background(), *id); err != nil {
		panic(err)
	}
	x, err := db.CreateAPIKey(context.Background(), *name, *role, raw)
	if err != nil {
		panic(err)
	}
	fmt.Printf("name=%s role=%s key=%s\n", x.Name, x.Role, raw)
}

func demoCommand(args []string) {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	addr := fs.String("listen", ":8080", "address")
	dbPath := fs.String("db", "data/triage.db", "SQLite database path")
	fs.Parse(args)
	run([]string{"--file", "testdata/example.ndjson", "--db", *dbPath})
	serve([]string{"--listen", *addr, "--db", *dbPath})
}

func evalCommand(args []string) {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	dataset := fs.String("dataset", "", "feedback JSONL dataset")
	fs.Parse(args)
	if *dataset == "" {
		fmt.Fprintln(os.Stderr, "--dataset is required")
		os.Exit(2)
	}
	f, e := os.Open(*dataset)
	if e != nil {
		panic(e)
	}
	defer f.Close()
	r, e := eval.Run(f)
	if e != nil {
		panic(e)
	}
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		panic(e)
	}
	fmt.Println(string(b))
}

func feedbackExport(args []string) {
	fs := flag.NewFlagSet("feedback export", flag.ExitOnError)
	dbPath := fs.String("db", "data/triage.db", "SQLite database path")
	out := fs.String("out", "", "JSONL output path")
	fs.Parse(args)
	db, e := store.Open(*dbPath)
	if e != nil {
		panic(e)
	}
	defer db.Close()
	rows, e := db.ListFeedback(context.Background())
	if e != nil {
		panic(e)
	}
	var w *os.File
	if *out != "" {
		w, e = os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if e != nil {
			panic(e)
		}
		defer w.Close()
	} else {
		w = os.Stdout
	}
	enc := json.NewEncoder(w)
	for _, r := range rows {
		if e = enc.Encode(r); e != nil {
			panic(e)
		}
	}
}

func reportCommand(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	dbPath := fs.String("db", "data/triage.db", "SQLite database path")
	period := fs.String("period", "7d", "period: 24h, 7d, 30d")
	out := fs.String("out", "", "output markdown path")
	format := fs.String("format", "md", "format: md, pdf or docx")
	fs.Parse(args)
	if *format != "md" && *format != "pdf" && *format != "docx" {
		fmt.Fprintln(os.Stderr, "format must be md, pdf or docx")
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
	var data []byte
	if *format == "md" {
		text, err := report.Markdown(context.Background(), db, d)
		if err != nil {
			panic(err)
		}
		data = []byte(text)
	}
	if *format == "pdf" {
		data, e = report.PDF(context.Background(), db, d)
	}
	if *format == "docx" {
		data, e = report.DOCX(context.Background(), db, d)
	}
	if e != nil {
		panic(e)
	}
	if *out != "" {
		if e = os.WriteFile(*out, data, 0600); e != nil {
			panic(e)
		}
	} else {
		if *format == "md" {
			fmt.Print(string(data))
		} else {
			_, _ = os.Stdout.Write(data)
		}
	}
}
