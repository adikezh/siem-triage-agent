package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type Alert struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	RuleID    string         `json:"rule_id"`
	RuleLevel int            `json:"rule_level"`
	Agent     map[string]any `json:"agent"`
	SrcIP     string         `json:"src_ip"`
}
type Incident struct {
	Fingerprint string    `json:"fingerprint"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	AlertCount  int       `json:"alert_count"`
	Score       int       `json:"score"`
	Severity    string    `json:"severity"`
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
	fs.Parse(args)
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
		alerts = append(alerts, a)
	}
	sortAlerts(alerts)
	inc := group(alerts)
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
	m := map[string]int{}
	var out []Incident
	for _, a := range as {
		agent, _ := a.Agent["id"].(string)
		fp := a.RuleID + "|" + agent + "|" + a.SrcIP
		i, ok := m[fp]
		if !ok || a.Timestamp.Sub(out[i].LastSeen) > 15*time.Minute || a.Timestamp.Sub(out[i].FirstSeen) > 6*time.Hour {
			out = append(out, Incident{Fingerprint: fp, FirstSeen: a.Timestamp, LastSeen: a.Timestamp, AlertCount: 1, Score: score(a.RuleLevel), Severity: severity(score(a.RuleLevel))})
			m[fp] = len(out) - 1
		} else {
			out[i].LastSeen = a.Timestamp
			out[i].AlertCount++
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
	fs.Parse(args)
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	fmt.Println("listening on", *addr)
	if e := http.ListenAndServe(*addr, nil); e != nil {
		panic(e)
	}
}
func usage() {
	fmt.Println("triage run --file alerts.ndjson [--out report.json]\ntriage serve [--listen :8080]\ntriage version")
}
