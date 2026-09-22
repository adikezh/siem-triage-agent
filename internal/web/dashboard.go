package web

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/adikezh/siem-triage-agent/internal/store"
)

var page = template.Must(template.New("dashboard").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>SIEM Triage</title><style>body{font:16px system-ui;margin:2rem;background:#f6f7f9;color:#18212b}main{max-width:1100px;margin:auto}table,.card{width:100%;background:white;border-collapse:collapse;padding:1rem}.card{box-sizing:border-box}th,td{padding:.7rem;border-bottom:1px solid #ddd;text-align:left}.severity{font-weight:700}.actions{display:flex;gap:.5rem;margin:1rem 0}button{padding:.5rem .8rem}pre{white-space:pre-wrap;overflow:auto;background:#f0f2f5;padding:1rem}.filters{background:white;padding:1rem;margin:1rem 0}</style></head><body><main><h1>SIEM Triage</h1><p><a href="/">All incidents</a></p>{{if .Detail}}<section class="card"><h2>{{.Detail.Severity}} — {{.Detail.ID}}</h2><p><b>Fingerprint:</b> {{.Detail.Fingerprint}}</p><p><b>Score:</b> {{.Detail.Score}} &nbsp; <b>Alerts:</b> {{.Detail.AlertCount}}</p><p><b>First seen:</b> {{.Detail.FirstSeen}}<br><b>Last seen:</b> {{.Detail.LastSeen}}</p><div class="actions"><form method="post" action="/incidents/{{.Detail.ID}}/feedback"><button name="verdict" value="tp">✅ TP</button><button name="verdict" value="fp">❌ FP</button><button name="verdict" value="ack">👁 Ack</button></form></div><h3>Incident payload / timeline</h3><pre>{{.Detail.Payload}}</pre></section>{{else}}<section class="filters"><form method="get" action="/"><label>Severity <select name="severity"><option value="">all</option><option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option></select></label> <label>Since <input name="since" placeholder="2026-09-23T00:00:00Z"></label> <label>Limit <input name="limit" type="number" min="1" max="1000"></label> <button>Filter</button></form><p>Total shown: {{len .Rows}} | Low: {{index .Counts "low"}} | Medium: {{index .Counts "medium"}} | High: {{index .Counts "high"}} | Critical: {{index .Counts "critical"}}</p></section>{{if .Rows}}<table><thead><tr><th>Fingerprint</th><th>Severity</th><th>Score</th><th>Alerts</th><th>Last seen</th></tr></thead><tbody>{{range .Rows}}<tr><td><a href="/incidents/{{.ID}}">{{.Fingerprint}}</a></td><td class="severity">{{.Severity}}</td><td>{{.Score}}</td><td>{{.AlertCount}}</td><td>{{.LastSeen}}</td></tr>{{end}}</tbody></table>{{else}}<p>No incidents yet.</p>{{end}}{{end}}</main></body></html>`))

type viewModel struct {
	Rows   []store.Record
	Detail *store.Record
	Counts map[string]int
}

func Handler(s *store.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if strings.HasPrefix(path, "incidents/") {
			parts := strings.Split(strings.TrimPrefix(path, "incidents/"), "/")
			id := parts[0]
			if id == "" {
				http.NotFound(w, r)
				return
			}
			if len(parts) == 2 && parts[1] == "feedback" {
				if r.Method != http.MethodPost {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				if err := r.ParseForm(); err != nil {
					http.Error(w, "invalid form", http.StatusBadRequest)
					return
				}
				verdict := r.FormValue("verdict")
				if verdict != "tp" && verdict != "fp" && verdict != "ack" {
					http.Error(w, "invalid verdict", http.StatusBadRequest)
					return
				}
				if err := s.AddFeedback(r.Context(), id, verdict, "", "web"); err != nil {
					http.Error(w, "could not save feedback", http.StatusInternalServerError)
					return
				}
				http.Redirect(w, r, "/incidents/"+id, http.StatusSeeOther)
				return
			}
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			record, err := s.GetIncident(r.Context(), id)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			record.Payload = []byte(template.HTMLEscapeString(string(record.Payload)))
			w.Header().Set("content-type", "text/html; charset=utf-8")
			_ = page.Execute(w, viewModel{Detail: &record})
			return
		}
		if r.URL.Path != "/" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		severity, since := q.Get("severity"), q.Get("since")
		limit := 0
		if severity != "" && severity != "low" && severity != "medium" && severity != "high" && severity != "critical" {
			http.Error(w, "invalid severity", http.StatusBadRequest)
			return
		}
		if since != "" {
			if _, err := time.Parse(time.RFC3339, since); err != nil {
				http.Error(w, "invalid since", http.StatusBadRequest)
				return
			}
		}
		if raw := q.Get("limit"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 1000 {
				http.Error(w, "invalid limit", http.StatusBadRequest)
				return
			}
			limit = n
		}
		rows, err := s.ListIncidentsFiltered(r.Context(), severity, since, limit)
		if err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		w.Header().Set("content-type", "text/html; charset=utf-8")
		counts := map[string]int{}
		for _, row := range rows {
			counts[row.Severity]++
		}
		_ = page.Execute(w, viewModel{Rows: rows, Counts: counts})
	})
}
